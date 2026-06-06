package main

import (
	"bytes"
	"net"
	"testing"
)

func TestIsDisallowedUpstreamIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},        // loopback
		{"::1", true},              // loopback v6
		{"10.0.0.1", true},         // RFC1918
		{"172.16.0.1", true},       // RFC1918
		{"192.168.1.1", true},      // RFC1918
		{"169.254.169.254", true},  // link-local (cloud metadata)
		{"100.64.0.1", true},       // CGNAT (RFC6598) — the gap we closed
		{"100.127.255.255", true},  // CGNAT upper
		{"192.0.0.1", true},        // IETF protocol assignments
		{"0.0.0.0", true},          // unspecified
		{"224.0.0.1", true},        // multicast
		{"::ffff:127.0.0.1", true}, // IPv4-mapped loopback
		{"::ffff:10.0.0.1", true},  // IPv4-mapped RFC1918
		{"8.8.8.8", false},         // public
		{"1.1.1.1", false},         // public
		{"100.63.255.255", false},  // just below CGNAT
		{"100.128.0.0", false},     // just above CGNAT
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := isDisallowedUpstreamIP(ip); got != tc.want {
			t.Errorf("isDisallowedUpstreamIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestValidateProxyUpstream(t *testing.T) {
	// IP-literal hosts so no DNS lookup is needed.
	bad := []string{
		"",                    // missing url
		"file:///etc/passwd",  // unsupported scheme (also blocks LFI)
		"ftp://example.com",   // unsupported scheme
		"http://localhost/",   // localhost
		"http://foo.local/",   // .local
		"http://127.0.0.1/",   // loopback
		"http://10.0.0.1/x",   // private
		"http://169.254.0.1/", // link-local
		"http://100.64.0.1/",  // CGNAT
		"https://[::1]/",      // loopback v6
		"http://0.0.0.0/",     // unspecified
	}
	for _, raw := range bad {
		if _, err := validateProxyUpstream(raw); err == nil {
			t.Errorf("validateProxyUpstream(%q) = nil error, want error", raw)
		}
	}

	good := []string{
		"http://8.8.8.8/list.txt",
		"https://1.1.1.1/rules",
	}
	for _, raw := range good {
		if _, err := validateProxyUpstream(raw); err != nil {
			t.Errorf("validateProxyUpstream(%q) = %v, want nil", raw, err)
		}
	}
}

func TestConvertRawListToRuleProvider(t *testing.T) {
	withRules, has := convertRawListToRuleProvider([]byte("DOMAIN,example.com\n# a comment\nIP-CIDR,1.1.1.0/24\n"))
	if !has {
		t.Fatal("expected hasRules=true")
	}
	if !bytes.Contains(withRules, []byte("payload:")) || !bytes.Contains(withRules, []byte(" - DOMAIN,example.com")) {
		t.Fatalf("expected payload + rule lines, got:\n%s", withRules)
	}

	// Comment-only and empty inputs must still produce a valid payload mapping.
	for _, in := range []string{"# only a comment\n\n", ""} {
		out, has := convertRawListToRuleProvider([]byte(in))
		if has {
			t.Errorf("input %q: expected hasRules=false", in)
		}
		if !bytes.Contains(out, []byte("payload: []")) {
			t.Errorf("input %q: expected 'payload: []', got:\n%s", in, out)
		}
		if bytes.Contains(out, []byte("\n - ")) {
			t.Errorf("input %q: unexpected rule line in degenerate output:\n%s", in, out)
		}
	}
}
