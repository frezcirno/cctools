package clash

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeTempUpstream writes a minimal valid Clash upstream YAML to a temp file
// and returns a file:// URL pointing at it, for exercising the fetch pipeline
// without network access.
func writeTempUpstream(t *testing.T, proxiesYAML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upstream.yaml")
	if err := os.WriteFile(path, []byte(proxiesYAML), 0644); err != nil {
		t.Fatalf("write temp upstream: %v", err)
	}
	return "file://" + path
}

const minimalUpstreamYAML = `proxies:
  - name: node1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret
proxy-groups: []
`

func TestCollectSelectsIncludesCustomChainsInOrder(t *testing.T) {
	cfg := Config{
		Template: map[string]any{
			"rules": []any{
				"GEOSITE,openai,CHATBOT",
				"DOMAIN-SUFFIX,live.com,ONEDRIVE",
				"MATCH,UNKNOWN",
				"IP-CIDR,1.1.1.0/24,STREAMING,no-resolve",
				"AND,((DOMAIN,foo.com),(NETWORK,UDP)),COMPLEX",
				123,
			},
		},
	}

	got := cfg.collectSelects()
	want := []string{"PROXY", "CHATBOT", "ONEDRIVE", "STREAMING", "COMPLEX", "UDP", "UNKNOWN", "CNSITE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectSelects() = %v, want %v", got, want)
	}
}

func TestExtractRuleTargetSupportsMultipleClashRuleForms(t *testing.T) {
	tests := []struct {
		rule string
		want string
		ok   bool
	}{
		{rule: "MATCH,UNKNOWN", want: "UNKNOWN", ok: true},
		{rule: "DOMAIN-SUFFIX,google.com,PROXY", want: "PROXY", ok: true},
		{rule: "IP-CIDR,1.1.1.0/24,CHATBOT,no-resolve", want: "CHATBOT", ok: true},
		{rule: "RULE-SET,openai,CHATBOT", want: "CHATBOT", ok: true},
		{rule: "AND,((DOMAIN,foo.com),(NETWORK,UDP)),COMPLEX", want: "COMPLEX", ok: true},
		{rule: "NOT,((DOMAIN,foo.com)),REJECT", want: "REJECT", ok: true},
		{rule: "", want: "", ok: false},
	}

	for _, tc := range tests {
		got, ok := extractRuleTarget(tc.rule)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("extractRuleTarget(%q) = (%q, %v), want (%q, %v)", tc.rule, got, ok, tc.want, tc.ok)
		}
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func TestAirportSpecEnabledDefaultsToTrueWhenMissing(t *testing.T) {
	var spec AirportSpec
	if err := yaml.Unmarshal([]byte("name: demo\nurls: [https://example.com]\n"), &spec); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if !spec.Enabled() {
		t.Fatalf("Enabled() = false, want true when enable is missing")
	}
}

func TestAirportSpecEnabledHonorsExplicitFalse(t *testing.T) {
	spec := AirportSpec{Enable: boolPtr(false)}
	if spec.Enabled() {
		t.Fatalf("Enabled() = true, want false")
	}
}

func TestAirportSpecReadsTagField(t *testing.T) {
	var spec AirportSpec
	if err := yaml.Unmarshal([]byte("name: demo\ntag: [default, test]\nurls: [https://example.com]\n"), &spec); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	want := []string{"default", "test", "demo", "all"}
	if got := spec.AllTags(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AllTags() = %v, want %v", got, want)
	}
}

func TestDeepCopyTemplateCreatesIndependentCopy(t *testing.T) {
	src := map[string]any{
		"dns": map[string]any{
			"enable": false,
		},
		"rules": []any{"MATCH,DIRECT"},
	}

	copyTpl, err := deepCopyTemplate(src)
	if err != nil {
		t.Fatalf("deepCopyTemplate() error = %v", err)
	}

	dnsMap, err := asStringAnyMapField(copyTpl, "dns")
	if err != nil {
		t.Fatalf("asStringAnyMapField(copyTpl, dns) error = %v", err)
	}
	dnsMap["enable"] = true
	copyTpl["dns"] = dnsMap

	srcDNS, err := asStringAnyMapField(src, "dns")
	if err != nil {
		t.Fatalf("asStringAnyMapField(src, dns) error = %v", err)
	}
	if srcDNS["enable"] != false {
		t.Fatalf("source template mutated, dns.enable = %v, want false", srcDNS["enable"])
	}
}

// TestGenerateValidatesBeforeFetching checks that Generate runs validation
// itself — callers no longer call a separate Validate — and reports the failure
// as *InvalidConfigError without touching any upstream.
func TestGenerateValidatesBeforeFetching(t *testing.T) {
	base := BaseURL{Scheme: "http", Host: "example.com"}
	upstreams := map[string]AirportSpec{
		// A URL that must never be fetched: reaching it means validation was
		// skipped, and the fetch would fail the test with a different error.
		"t": {Name: "t", Urls: []string{"file:///nonexistent/must-not-be-read.yaml"}},
	}

	cases := map[string]Config{
		"port out of range": {Upstreams: upstreams, HttpPort: 70000},
		"bad enhanced_mode": {Upstreams: upstreams, EnhancedMode: "nope"},
		"tun without stack": {Upstreams: upstreams, Tun: true},
		"dns without listen": {
			Upstreams: upstreams, Dns: true, EnhancedMode: "fake-ip", Nameserver: []string{"1.1.1.1"},
		},
		"missing upstreams": {},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := cfg
			_, err := cfg.Generate(base)
			if err == nil {
				t.Fatalf("Generate() error = nil, want *InvalidConfigError")
			}
			var invalid *InvalidConfigError
			if !errors.As(err, &invalid) {
				t.Fatalf("Generate() error = %T (%v), want *InvalidConfigError", err, err)
			}
		})
	}
}

func TestGenerateDoesNotMutateOriginalTemplate(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	originalTemplate := map[string]any{
		"rules": []any{
			"GEOSITE,openai,CHATBOT",
			"MATCH,UNKNOWN",
		},
		"proxy-groups": []any{},
		"proxies":      []any{},
		"dns": map[string]any{
			"enable": false,
		},
		"tun": map[string]any{
			"enable": false,
		},
	}

	upstreamURL := writeTempUpstream(t, minimalUpstreamYAML)
	cfg := Config{
		Template:                 originalTemplate,
		Upstream:                 []string{"all"},
		Upstreams:                map[string]AirportSpec{"t": {Name: "t", Urls: []string{upstreamURL}}},
		ExternalControllerSecret: "secret-1",
		RuleProviderTransform:    RPT_NONE,
		PortProxy:                true,
		AllowLan:                 true,
		BindAddress:              "127.0.0.1",
		MixedPort:                7890,
		Dns:                      true,
		DnsListen:                "127.0.0.1:53",
		EnhancedMode:             "fake-ip",
		Nameserver:               []string{"1.1.1.1"},
		Fallback:                 []string{"https://1.0.0.1/dns-query"},
	}

	base := BaseURL{Scheme: "http", Host: "example.com"}
	generated, err := cfg.Generate(base)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if generated["secret"] != "secret-1" {
		t.Fatalf("generated secret = %v, want secret-1", generated["secret"])
	}
	if generated["bind-address"] != "127.0.0.1" {
		t.Fatalf("generated bind-address = %v, want 127.0.0.1", generated["bind-address"])
	}
	if _, ok := originalTemplate["secret"]; ok {
		t.Fatalf("original template unexpectedly mutated with secret field")
	}

	origDNS, err := asStringAnyMapField(originalTemplate, "dns")
	if err != nil {
		t.Fatalf("asStringAnyMapField(originalTemplate, dns) error = %v", err)
	}
	if origDNS["enable"] != false {
		t.Fatalf("original dns.enable = %v, want false", origDNS["enable"])
	}
}

func TestExpandRuleSetPatterns(t *testing.T) {
	tests := []struct {
		name      string
		behavior  string
		patterns  []string
		action    string
		noResolve bool
		want      []string
		wantError bool
	}{
		{
			name:     "classical keeps raw rule",
			behavior: "classical",
			patterns: []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,1.1.1.0/24,no-resolve"},
			action:   "PROXY",
			want: []string{
				"DOMAIN-SUFFIX,example.com,PROXY",
				"IP-CIDR,1.1.1.0/24,PROXY,no-resolve",
			},
		},
		{
			name:     "domain behavior prefixes domain",
			behavior: "domain",
			patterns: []string{"example.com"},
			action:   "CHATBOT",
			want:     []string{"DOMAIN,example.com,CHATBOT"},
		},
		{
			name:      "ipcidr behavior carries the rule-set's no-resolve",
			behavior:  "ipcidr",
			patterns:  []string{"1.2.3.0/24"},
			action:    "REJECT",
			noResolve: true,
			want:      []string{"IP-CIDR,1.2.3.0/24,REJECT,no-resolve"},
		},
		{
			name:     "ipcidr behavior without no-resolve stays resolving",
			behavior: "ipcidr",
			patterns: []string{"1.2.3.0/24"},
			action:   "CNSITE",
			want:     []string{"IP-CIDR,1.2.3.0/24,CNSITE"},
		},
		{
			name:      "classical no-resolve touches IP rules only, never twice",
			behavior:  "classical",
			patterns:  []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,1.1.1.0/24", "IP-CIDR6,2001:db8::/32,no-resolve", "GEOIP,CN"},
			action:    "REJECT",
			noResolve: true,
			want: []string{
				"DOMAIN-SUFFIX,example.com,REJECT",
				"IP-CIDR,1.1.1.0/24,REJECT,no-resolve",
				"IP-CIDR6,2001:db8::/32,REJECT,no-resolve",
				"GEOIP,CN,REJECT,no-resolve",
			},
		},
		{
			name:      "unknown behavior fails",
			behavior:  "wat",
			patterns:  []string{"example.com"},
			action:    "PROXY",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandRuleSetPatterns(tc.behavior, tc.patterns, tc.action, tc.noResolve)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expandRuleSetPatterns() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expandRuleSetPatterns() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expandRuleSetPatterns() = %v, want %v", got, tc.want)
			}
		})
	}
}

func makeDictList(entries ...YamlStrDict) DictList {
	dl := NewEmptyDictList()
	for _, entry := range entries {
		name := entry["name"].(string)
		dl.Set(name, entry)
	}
	return dl
}

func TestOrganizeProxiesUsesOrganizerRegistry(t *testing.T) {
	proxies := makeDictList(
		YamlStrDict{"name": "香港节点", "udp": true},
		YamlStrDict{"name": "台湾节点", "udp": false},
		YamlStrDict{"name": "us-node", "udp": true},
		YamlStrDict{"name": "sg-node", "udp": false},
		YamlStrDict{"name": "日本节点", "udp": false},
	)

	classified := OrganizeNodes(proxies, DefaultNodeOrganizers)

	if !reflect.DeepEqual(classified["cn"], []string{"香港节点", "台湾节点"}) {
		t.Fatalf("classified cn = %v", classified["cn"])
	}
	if !reflect.DeepEqual(classified["tw"], []string{"台湾节点"}) {
		t.Fatalf("classified tw = %v", classified["tw"])
	}
	if !isHK(proxies.Get("香港节点")) || isHK(proxies.Get("台湾节点")) {
		t.Fatalf("isHK() matcher is incorrect")
	}
	if !reflect.DeepEqual(classified["us"], []string{"us-node"}) {
		t.Fatalf("classified us = %v", classified["us"])
	}
	if !reflect.DeepEqual(classified["sg"], []string{"sg-node"}) {
		t.Fatalf("classified sg = %v", classified["sg"])
	}
	if !reflect.DeepEqual(classified["jp"], []string{"日本节点"}) {
		t.Fatalf("classified jp = %v", classified["jp"])
	}
	if !reflect.DeepEqual(classified["oversea"], []string{"us-node", "sg-node", "日本节点"}) {
		t.Fatalf("classified oversea = %v", classified["oversea"])
	}
	udpGot := append([]string(nil), classified["udp"]...)
	if len(udpGot) != 2 {
		t.Fatalf("classified udp len = %d, want 2; values=%v", len(udpGot), udpGot)
	}
	gotSet := map[string]bool{}
	for _, item := range udpGot {
		gotSet[item] = true
	}
	if !gotSet["香港节点"] || !gotSet["us-node"] {
		t.Fatalf("classified udp = %v", classified["udp"])
	}
}

func TestApplyBaseTemplateOptionsSetsLogLevel(t *testing.T) {
	cfg := Config{
		Template: map[string]any{},
		LogLevel: "debug",
	}
	if err := cfg.applyBaseTemplateOptions(); err != nil {
		t.Fatalf("applyBaseTemplateOptions() error = %v", err)
	}
	if cfg.Template["log-level"] != "debug" {
		t.Fatalf("log-level = %v, want debug", cfg.Template["log-level"])
	}
}

// TestParseUpstreamRejectsMalformedProxiesWithoutPanicking guards the bug where
// malformed third-party YAML used to panic the fetch goroutine and crash the
// whole process. parseUpstream must now return an error instead.
func TestParseUpstreamRejectsMalformedProxiesWithoutPanicking(t *testing.T) {
	cases := map[string]string{
		"null element":   "proxies: [null]\n",
		"scalar element": "proxies:\n  - just-a-string\n",
		"missing name":   "proxies:\n  - {type: ss, server: 1.2.3.4}\n",
	}
	for name, content := range cases {
		if _, err := parseUpstream([]byte(content)); err == nil {
			t.Errorf("%s: parseUpstream returned nil error, want error (must not panic)", name)
		}
	}

	// A well-formed upstream with no proxy-groups should still parse fine.
	if _, err := parseUpstream([]byte(minimalUpstreamYAML)); err != nil {
		t.Fatalf("valid upstream errored: %v", err)
	}
}

// TestGenerateIsDeterministic verifies identical requests produce byte-identical
// output, including a stable suffix for cross-upstream name collisions.
func TestGenerateIsDeterministic(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	up1 := writeTempUpstream(t, `proxies:
  - {name: shared, type: ss, server: 1.1.1.1, port: 1, cipher: aes-256-gcm, password: x}
  - {name: a-only, type: ss, server: 1.1.1.2, port: 1, cipher: aes-256-gcm, password: x}
`)
	up2 := writeTempUpstream(t, `proxies:
  - {name: shared, type: ss, server: 2.2.2.1, port: 1, cipher: aes-256-gcm, password: x}
  - {name: b-only, type: ss, server: 2.2.2.2, port: 1, cipher: aes-256-gcm, password: x}
`)

	newCfg := func() Config {
		return Config{
			Template:  map[string]any{"rules": []any{"MATCH,PROXY"}, "proxy-groups": []any{}, "proxies": []any{}},
			Upstream:  []string{"all"},
			Upstreams: map[string]AirportSpec{"aaa": {Name: "aaa", Urls: []string{up1}}, "bbb": {Name: "bbb", Urls: []string{up2}}},
		}
	}
	base := BaseURL{Scheme: "http", Host: "example.com"}

	render := func() []byte {
		cfg := newCfg()
		out, err := cfg.Generate(base)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		b, err := yaml.Marshal(out)
		if err != nil {
			t.Fatalf("marshal error = %v", err)
		}
		return b
	}

	first := render()
	for i := 0; i < 3; i++ {
		if got := render(); !bytes.Equal(first, got) {
			t.Fatalf("Generate() output is not deterministic across runs")
		}
	}
	// The "bbb" airport's colliding "shared" proxy must get the deterministic suffix.
	if !bytes.Contains(first, []byte("shared_2")) {
		t.Fatalf("expected deterministic collision suffix 'shared_2' in output:\n%s", first)
	}
}

func TestBuildOrganizerGroupsOnlyEmitsRequestedGroups(t *testing.T) {
	cfg := Config{Organizer: []string{"udp", "tw", "us"}}
	proxies := makeDictList(
		YamlStrDict{"name": "台湾节点", "udp": false},
		YamlStrDict{"name": "us-node", "udp": true},
	)

	groups := cfg.buildOrganizerGroups("all", proxies)
	gotNames := make([]string, 0, len(groups))
	for _, group := range groups {
		name, err := asString(group["name"], "group.name")
		if err != nil {
			t.Fatalf("group name error = %v", err)
		}
		gotNames = append(gotNames, name)
	}

	wantNames := []string{"all-tw", "all-us", "all-udp"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("group names = %v, want %v", gotNames, wantNames)
	}
}

// groupNames returns the names of the built proxy-groups, in output order.
func groupNames(groups []YamlStrDict) []string {
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g["name"].(string))
	}
	return names
}

func hasPrefixIn(names []string, prefix string) bool {
	for _, n := range names {
		if n == prefix || strings.HasPrefix(n, prefix+"-") {
			return true
		}
	}
	return false
}

// With one airport the "all" scope duplicates that airport's groups node for
// node, so it is dropped: keeping it would health-check every proxy twice.
func TestBuildProxyGroupsSkipsAllScopeForSingleAirport(t *testing.T) {
	proxies := makeDictList(
		YamlStrDict{"name": "US-01", "udp": true},
		YamlStrDict{"name": "JP-01"},
	)
	cfg := Config{Organizer: []string{"us", "udp"}}
	airports := map[string]*Airport{"solo": {Proxies: proxies}}

	names := groupNames(cfg.buildProxyGroups(airports, proxies, []string{"PROXY"}))

	if hasPrefixIn(names, "all") {
		t.Fatalf("single airport should not emit an \"all\" scope, got %v", names)
	}
	for _, want := range []string{"solo", "solo-us", "solo-udp"} {
		if !slices.Contains(names, want) {
			t.Fatalf("missing group %q in %v", want, names)
		}
	}
}

// With more than one airport the "all" scope is what merges them, so it stays.
func TestBuildProxyGroupsKeepsAllScopeForMultipleAirports(t *testing.T) {
	a := makeDictList(YamlStrDict{"name": "US-01"})
	b := makeDictList(YamlStrDict{"name": "JP-01"})
	merged := makeDictList(YamlStrDict{"name": "US-01"}, YamlStrDict{"name": "JP-01"})
	cfg := Config{Organizer: []string{"us"}}
	airports := map[string]*Airport{"one": {Proxies: a}, "two": {Proxies: b}}

	names := groupNames(cfg.buildProxyGroups(airports, merged, []string{"PROXY"}))

	for _, want := range []string{"all", "all-us", "one", "two"} {
		if !slices.Contains(names, want) {
			t.Fatalf("missing group %q in %v", want, names)
		}
	}
}

// Every override probes a Cloudflare-fronted service, where a geo-blocked node
// still answers (claude.ai replies 403 with a challenge page). Without an
// expected status mihomo counts that as alive and the probe silently decays
// into a costly generate_204, so the pairing is mandatory.
func TestHealthCheckOverridesPinAnExpectedStatus(t *testing.T) {
	for _, override := range healthCheckOverrides {
		if override.expectedStatus == "" {
			t.Errorf("override %q (%s) has no expectedStatus, so a blocked node would still rank as alive",
				override.suffix, override.url)
		}
	}
}

// The default probe returns 204, so it must not carry an expected status, while
// an overridden group must.
func TestMakeURLTestGroupEmitsExpectedStatusOnlyWhenOverridden(t *testing.T) {
	plain := makeURLTestGroup("paoluz-us", []string{"n1"})
	if _, ok := plain["expected-status"]; ok {
		t.Errorf("default group should not pin a status, got %v", plain["expected-status"])
	}
	if plain["url"] != defaultURLTestURL {
		t.Errorf("default group url = %v, want %v", plain["url"], defaultURLTestURL)
	}

	claude := makeURLTestGroup("paoluz-claude", []string{"n1"})
	if claude["expected-status"] != "200" {
		t.Errorf("claude group expected-status = %v, want 200", claude["expected-status"])
	}
	if !strings.Contains(claude["url"].(string), "claude.ai") {
		t.Errorf("claude group should probe claude.ai, got %v", claude["url"])
	}
}

func TestRouteFallbackThroughProxy(t *testing.T) {
	got := routeFallbackThroughProxy([]string{
		"https://1.0.0.1/dns-query",
		"https://dns.example/dns-query#DIRECT",
		"tls://8.8.8.8#PROXY&h3=true",
		"",
	})
	want := []string{
		"https://1.0.0.1/dns-query#PROXY",
		"https://dns.example/dns-query#DIRECT",
		"tls://8.8.8.8#PROXY&h3=true",
		"",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routeFallbackThroughProxy() = %v, want %v", got, want)
	}
}

func TestApplyDNSOptionsRoutesFallbackThroughProxy(t *testing.T) {
	cfg := Config{
		Template:   DefaultTemplate(),
		Dns:        true,
		Nameserver: []string{"223.5.5.5"},
		Fallback:   []string{"https://1.0.0.1/dns-query"},
	}
	if err := cfg.applyDNSOptions(); err != nil {
		t.Fatalf("applyDNSOptions() error = %v", err)
	}
	dns, err := asStringAnyMapField(cfg.Template, "dns")
	if err != nil {
		t.Fatalf("dns block: %v", err)
	}
	if got, want := dns["fallback"], []string{"https://1.0.0.1/dns-query#PROXY"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dns.fallback = %v, want %v", got, want)
	}
	if got, want := dns["nameserver"], []string{"223.5.5.5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dns.nameserver = %v, want %v (only fallback is proxied)", got, want)
	}
}

// Every domain that reaches an IP rule without no-resolve is resolved locally
// first. The proxy-only keywords for the dns.fallback-filter domains must
// therefore match before the first such rule, or each new connection to them
// pays a fallback DNS lookup (a 5s stall when the fallback is unreachable).
func TestDefaultTemplateMatchesFallbackDomainsBeforeResolvingIPRules(t *testing.T) {
	tmpl := DefaultTemplate()
	rules, ok := tmpl["rules"].([]any)
	if !ok {
		t.Fatal("default template has no rules")
	}
	providers, err := asStringAnyMapField(tmpl, "rule-providers")
	if err != nil {
		t.Fatalf("rule-providers: %v", err)
	}
	firstResolving := -1
	for i, raw := range rules {
		rule, _ := raw.(string)
		parts := strings.Split(rule, ",")
		if slices.Contains(parts, "no-resolve") {
			continue
		}
		switch {
		case parts[0] == "GEOIP", strings.HasPrefix(parts[0], "IP-"):
		case parts[0] == "RULE-SET" && len(parts) > 1:
			provider, _ := providers[parts[1]].(map[string]any)
			if provider["behavior"] != "ipcidr" {
				continue
			}
		default:
			continue
		}
		firstResolving = i
		break
	}
	if firstResolving < 0 {
		t.Fatal("no resolving IP rule found; the test no longer guards anything")
	}
	for _, want := range []string{"DOMAIN-KEYWORD,google,PROXY", "DOMAIN-KEYWORD,youtube,PROXY", "DOMAIN-KEYWORD,facebook,PROXY"} {
		idx := slices.Index(rules, any(want))
		if idx < 0 {
			t.Errorf("rule %q missing from default template", want)
			continue
		}
		if idx > firstResolving {
			t.Errorf("rule %q at %d comes after resolving IP rule %v at %d", want, idx, rules[firstResolving], firstResolving)
		}
	}
}

func TestMakeURLTestGroupDetectsDeadNodesPromptly(t *testing.T) {
	for _, name := range []string{"paoluz-us", "paoluz-claude"} {
		g := makeURLTestGroup(name, []string{"n1"})
		interval, ok := g["interval"].(int)
		if !ok || interval <= 0 || interval > 600 {
			t.Errorf("%s interval = %v, want 1..600s so a silently dead node is replaced within minutes", name, g["interval"])
		}
		if g["lazy"] != true {
			t.Errorf("%s lazy = %v, want true (the short interval is only affordable for groups in use)", name, g["lazy"])
		}
		if g["max-failed-times"] != urlTestMaxFailedTimes {
			t.Errorf("%s max-failed-times = %v, want %d", name, g["max-failed-times"], urlTestMaxFailedTimes)
		}
	}
}

func TestSelectProxiesPutsClaudeGroupsFirstForClaude(t *testing.T) {
	groups := []string{"all", "all-us", "all-claude", "all-chatbot", "paoluz", "paoluz-claude", "zzy-claude"}
	original := slices.Clone(groups)

	got := selectProxies("CLAUDE", groups)
	want := []string{"all-claude", "paoluz-claude", "zzy-claude", "PROXY", "all", "all-us", "all-chatbot", "paoluz", "DIRECT"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectProxies(CLAUDE) = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(groups, original) {
		t.Fatalf("selectProxies mutated its input: %v", groups)
	}

	// Without the claude organizer there is nothing to prefer: PROXY stays first.
	if got := selectProxies("CLAUDE", []string{"all", "paoluz"}); !reflect.DeepEqual(got, []string{"PROXY", "all", "paoluz", "DIRECT"}) {
		t.Fatalf("selectProxies(CLAUDE) without claude groups = %v", got)
	}
	// Other custom chains keep PROXY as their default.
	if got := selectProxies("CHATBOT", groups); got[0] != "PROXY" {
		t.Fatalf("selectProxies(CHATBOT)[0] = %v, want PROXY", got[0])
	}
}
