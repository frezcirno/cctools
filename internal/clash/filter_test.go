package clash

import "testing"

func TestProxyNameMissing(t *testing.T) {
	proxy := YamlStrDict{"type": "ss"}
	if isCN(proxy) {
		t.Fatal("isCN should return false for proxy without name")
	}
	if isTW(proxy) {
		t.Fatal("isTW should return false for proxy without name")
	}
	if isHK(proxy) {
		t.Fatal("isHK should return false for proxy without name")
	}
	if isUS(proxy) {
		t.Fatal("isUS should return false for proxy without name")
	}
	if isSG(proxy) {
		t.Fatal("isSG should return false for proxy without name")
	}
	if isJP(proxy) {
		t.Fatal("isJP should return false for proxy without name")
	}
	if claudeOk(proxy) {
		t.Fatal("claudeOk should return false for proxy without name")
	}
	if isOversea(proxy) {
		// isOversea is !isCN, and isCN returns false, so isOversea returns true
		// This is expected behavior for missing name
	}
}

func TestProxyNameWrongType(t *testing.T) {
	proxy := YamlStrDict{"name": 123}
	if isCN(proxy) {
		t.Fatal("isCN should return false for non-string name")
	}
	if isUS(proxy) {
		t.Fatal("isUS should return false for non-string name")
	}
}

// organizerMatcher looks the predicate up through DefaultNodeOrganizers rather
// than calling it directly, so a renamed or rewired entry fails here instead of
// silently dropping the group from every generated config.
func organizerMatcher(t *testing.T, name string) func(YamlStrDict) bool {
	t.Helper()
	for _, organizer := range DefaultNodeOrganizers {
		if organizer.name == name {
			return organizer.matcher
		}
	}
	t.Fatalf("organizer %q not registered in DefaultNodeOrganizers", name)
	return nil
}

// The claude group takes any US node, plus nodes advertising AI unlocking.
func TestClaudeOrganizerTakesUSAndAINodes(t *testing.T) {
	matcher := organizerMatcher(t, "claude")

	match := []string{
		"US-01", "US-Claude-01", "🇺🇸 Anthropic 解锁", "美国克劳德",
		"JP|Claude/GPT", "美国AI解锁", "OpenAI|SG",
	}
	for _, name := range match {
		if !matcher(YamlStrDict{"name": name}) {
			t.Errorf("claude matcher(%q) = false, want true", name)
		}
	}

	// Bare "ai" inside a larger word must not match, or Dubai/Shanghai nodes
	// would leak in.
	noMatch := []string{"香港 IEPL", "JP-Tokyo-01", "Dubai-01", "Shanghai IPLC"}
	for _, name := range noMatch {
		if matcher(YamlStrDict{"name": name}) {
			t.Errorf("claude matcher(%q) = true, want false", name)
		}
	}
}

// The chatgpt group selects on geography — anything outside CN/HK/TW — rather
// than on an advertised AI-unlock label.
func TestChatgptOrganizerTakesOverseaNodes(t *testing.T) {
	matcher := organizerMatcher(t, "chatgpt")

	match := []string{"JP-Tokyo-01", "US-01", "SG 新加坡", "美国AI解锁", "Dubai-01"}
	for _, name := range match {
		if !matcher(YamlStrDict{"name": name}) {
			t.Errorf("chatgpt matcher(%q) = false, want true", name)
		}
	}

	noMatch := []string{"香港 IEPL", "🇭🇰 HK-01", "台湾 TW-02", "hong kong 02"}
	for _, name := range noMatch {
		if matcher(YamlStrDict{"name": name}) {
			t.Errorf("chatgpt matcher(%q) = true, want false", name)
		}
	}
}

func TestIsUDPMissingField(t *testing.T) {
	proxy := YamlStrDict{"name": "test"}
	if supportUDP(proxy) {
		t.Fatal("isUDP should return false when udp field is missing")
	}
}

func TestIsUDPWrongType(t *testing.T) {
	proxy := YamlStrDict{"name": "test", "udp": "yes"}
	if supportUDP(proxy) {
		t.Fatal("isUDP should return false for non-bool udp field")
	}
}

func TestIsUDPTrue(t *testing.T) {
	proxy := YamlStrDict{"name": "test", "udp": true}
	if !supportUDP(proxy) {
		t.Fatal("isUDP should return true")
	}
}
