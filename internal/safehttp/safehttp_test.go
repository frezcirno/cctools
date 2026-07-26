package safehttp

import (
	"net"
	"net/url"
	"testing"
)

func TestIsDisallowedIP(t *testing.T) {
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
		if got := IsDisallowedIP(ip); got != tc.want {
			t.Errorf("IsDisallowedIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestValidateUpstreamURL(t *testing.T) {
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
		if _, err := ValidateUpstreamURL(raw); err == nil {
			t.Errorf("ValidateUpstreamURL(%q) = nil error, want error", raw)
		}
	}

	good := []string{
		"http://8.8.8.8/list.txt",
		"https://1.1.1.1/rules",
	}
	for _, raw := range good {
		if _, err := ValidateUpstreamURL(raw); err != nil {
			t.Errorf("ValidateUpstreamURL(%q) = %v, want nil", raw, err)
		}
	}
}

func TestRedactURLStripsCredentials(t *testing.T) {
	u, err := url.Parse("https://user:pw@example.com/sub?token=secret#frag")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := RedactURL(u)
	want := "https://example.com/sub?REDACTED"
	if got != want {
		t.Fatalf("RedactURL() = %q, want %q", got, want)
	}
	if RedactURL(nil) != "" {
		t.Fatalf("RedactURL(nil) should be empty")
	}
}
