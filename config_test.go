package main

import (
	"net/http/httptest"
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestCollectSelectorsIncludesCustomChainsInOrder(t *testing.T) {
	cfg := Config{
		Template: map[string]any{
			"rules": []any{
				"GEOSITE,openai,CHATBOT",
				"DOMAIN-SUFFIX,live.com,ONEDRIVE",
				"MATCH,FALLBACK",
				"IP-CIDR,1.1.1.0/24,STREAMING,no-resolve",
				"AND,((DOMAIN,foo.com),(NETWORK,UDP)),COMPLEX",
				123,
			},
		},
	}

	got := cfg.collectSelectors()
	want := []string{"PROXY", "CHATBOT", "ONEDRIVE", "STREAMING", "COMPLEX", "UDP", "FALLBACK", "CNSITE"}
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
		{rule: "MATCH,FALLBACK", want: "FALLBACK", ok: true},
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
	if !spec.enabled() {
		t.Fatalf("enabled() = false, want true when enable is missing")
	}
}

func TestAirportSpecEnabledHonorsExplicitFalse(t *testing.T) {
	spec := AirportSpec{Enable: boolPtr(false)}
	if spec.enabled() {
		t.Fatalf("enabled() = true, want false")
	}
}

func TestAirportSpecReadsTagField(t *testing.T) {
	var spec AirportSpec
	if err := yaml.Unmarshal([]byte("name: demo\ntag: [default, test]\nurls: [https://example.com]\n"), &spec); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	want := []string{"default", "test", "demo", "all"}
	if got := spec.tags(); !reflect.DeepEqual(got, want) {
		t.Fatalf("tags() = %v, want %v", got, want)
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

func TestGenerateDoesNotMutateOriginalTemplate(t *testing.T) {
	originalTemplate := map[string]any{
		"rules": []any{
			"GEOSITE,openai,CHATBOT",
			"MATCH,FALLBACK",
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

	cfg := Config{
		Template:                 originalTemplate,
		Upstreams:                map[string]AirportSpec{},
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

	req := httptest.NewRequest("GET", "http://example.com/clash/config.yaml", nil)
	generated, err := cfg.generate(req)
	if err != nil {
		t.Fatalf("generate() error = %v", err)
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

func TestClassifyProxiesUsesClassifierRegistry(t *testing.T) {
	proxies := DictList{
		"香港节点":    YamlStrDict{"name": "香港节点", "udp": true},
		"台湾节点":    YamlStrDict{"name": "台湾节点", "udp": false},
		"us-node": YamlStrDict{"name": "us-node", "udp": true},
	}

	classified := classifyProxies(proxies, organizerClassifiers)

	if !reflect.DeepEqual(classified["cn"], []string{"香港节点", "台湾节点"}) {
		t.Fatalf("classified cn = %v", classified["cn"])
	}
	if !reflect.DeepEqual(classified["tw"], []string{"台湾节点"}) {
		t.Fatalf("classified tw = %v", classified["tw"])
	}
	if !isHK(proxies["香港节点"]) || isHK(proxies["台湾节点"]) {
		t.Fatalf("isHK() matcher is incorrect")
	}
	if !reflect.DeepEqual(classified["us"], []string{"us-node"}) {
		t.Fatalf("classified us = %v", classified["us"])
	}
	if !reflect.DeepEqual(classified["oversea"], []string{"us-node"}) {
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

func TestBuildOrganizerGroupsOnlyEmitsRequestedGroups(t *testing.T) {
	cfg := Config{Organizer: []string{"udp", "tw", "us"}}
	proxies := DictList{
		"台湾节点":    YamlStrDict{"name": "台湾节点", "udp": false},
		"us-node": YamlStrDict{"name": "us-node", "udp": true},
	}

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
