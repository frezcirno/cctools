package clash

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestCollectSelectorsIncludesCustomChainsInOrder(t *testing.T) {
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

	got := cfg.collectSelectors()
	want := []string{"PROXY", "CHATBOT", "ONEDRIVE", "STREAMING", "COMPLEX", "UDP", "UNKNOWN", "CNSITE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectSelectors() = %v, want %v", got, want)
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
			name:      "unknown behavior fails",
			behavior:  "wat",
			patterns:  []string{"example.com"},
			action:    "PROXY",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandRuleSetPatterns(tc.behavior, tc.patterns, tc.action)
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

func TestClassifyProxiesUsesClassifierRegistry(t *testing.T) {
	proxies := makeDictList(
		YamlStrDict{"name": "香港节点", "udp": true},
		YamlStrDict{"name": "台湾节点", "udp": false},
		YamlStrDict{"name": "us-node", "udp": true},
		YamlStrDict{"name": "sg-node", "udp": false},
		YamlStrDict{"name": "日本节点", "udp": false},
	)

	classified := ClassifyNodes(proxies, NodeClassifiers)

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
