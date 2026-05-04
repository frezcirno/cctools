package main

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

func TestIsUDPMissingField(t *testing.T) {
	proxy := YamlStrDict{"name": "test"}
	if isUDP(proxy) {
		t.Fatal("isUDP should return false when udp field is missing")
	}
}

func TestIsUDPWrongType(t *testing.T) {
	proxy := YamlStrDict{"name": "test", "udp": "yes"}
	if isUDP(proxy) {
		t.Fatal("isUDP should return false for non-bool udp field")
	}
}

func TestIsUDPTrue(t *testing.T) {
	proxy := YamlStrDict{"name": "test", "udp": true}
	if !isUDP(proxy) {
		t.Fatal("isUDP should return true")
	}
}
