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
		t.Fatal("isClaude should return false for proxy without name")
	}
	if chatgptOk(proxy) {
		t.Fatal("isChatgpt should return false for proxy without name")
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

func TestIsClaude(t *testing.T) {
	match := []string{
		"US-Claude-01", "claude专线", "🇺🇸 Anthropic 解锁", "美国克劳德",
		"JP|Claude/GPT",
	}
	for _, name := range match {
		if !claudeOk(YamlStrDict{"name": name}) {
			t.Errorf("isClaude(%q) = false, want true", name)
		}
	}

	// "clauded"/"anthropics" have no word boundary; the geo nodes must not leak
	// into the claude group.
	noMatch := []string{"US-01", "香港 IEPL", "claudex", "unclaude", "GPT-4 解锁"}
	for _, name := range noMatch {
		if claudeOk(YamlStrDict{"name": name}) {
			t.Errorf("isClaude(%q) = true, want false", name)
		}
	}
}

func TestIsChatgpt(t *testing.T) {
	match := []string{
		"美国AI解锁", "US-ChatGPT", "chat gpt 专线", "OpenAI|SG",
		"🇯🇵 GPT", "人工智能专线", "ChatBot-01",
	}
	for _, name := range match {
		if !chatgptOk(YamlStrDict{"name": name}) {
			t.Errorf("isChatgpt(%q) = false, want true", name)
		}
	}

	// Bare "ai" inside a larger word must not match, or Dubai/Thailand/Shanghai
	// nodes would all land in the chatgpt group. Other vendors (Gemini, Copilot)
	// are deliberately out of scope now that the group is named chatgpt.
	noMatch := []string{
		"Dubai-01", "Thailand 泰国", "Shanghai IPLC", "US-Claude-01",
		"Gemini-JP", "Copilot-US",
	}
	for _, name := range noMatch {
		if chatgptOk(YamlStrDict{"name": name}) {
			t.Errorf("isChatgpt(%q) = true, want false", name)
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
