// Package safehttp provides the outbound HTTP plumbing used for fetching
// untrusted URLs (subscription upstreams, rule-provider lists, /convert
// targets).
//
// Every connection is validated at dial time against the resolved IP, which
// closes the TOCTOU / DNS-rebinding gap that a pre-flight hostname check leaves
// open and re-validates each redirect hop.
package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// MaxResponseBytes caps how much we will buffer from any single upstream /
// rule-provider response, to bound memory use against hostile or huge bodies.
const MaxResponseBytes = 32 << 20 // 32 MiB

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Ranges net.IP.IsPrivate() does not cover but that we still want to block.
var (
	cgnatRange     = mustParseCIDR("100.64.0.0/10") // RFC 6598 carrier-grade NAT
	ietfProtoRange = mustParseCIDR("192.0.0.0/24")  // RFC 6890 IETF protocol assignments
)

// IsDisallowedIP reports whether an IP is in a range we refuse to fetch from
// (loopback, private, link-local incl. cloud metadata, CGNAT, multicast, ...).
func IsDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// To4 also normalizes IPv4-mapped IPv6 (::ffff:a.b.c.d) to its v4 form.
	if ip4 := ip.To4(); ip4 != nil {
		if cgnatRange.Contains(ip4) || ietfProtoRange.Contains(ip4) {
			return true
		}
	}
	return false
}

// dialer rejects connections to disallowed IPs at dial time — after DNS
// resolution, on the actual address about to be connected. This closes the
// TOCTOU / DNS-rebinding gap that a pre-flight net.LookupIP check leaves open,
// and (because it runs for every connection) also re-validates redirect hops.
var dialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("cannot parse dial address %q", address)
		}
		if IsDisallowedIP(ip) {
			return fmt.Errorf("disallowed dial IP %s", ip)
		}
		return nil
	},
}

// Transport is the shared IP-validating transport. Use it for reverse proxies,
// which need a Transport rather than a Client.
var Transport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           dialer.DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// Client is the shared client for all outbound fetches of untrusted URLs
// (upstreams and rule-providers). Redirects are followed but every hop is
// re-validated by the dialer's Control hook.
var Client = &http.Client{
	Transport: Transport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	},
}

// ValidateUpstreamURL parses raw and rejects it unless it is an http(s) URL
// pointing at a publicly routable host. This is a pre-flight check only —
// the dialer re-validates the address actually connected to.
func ValidateUpstreamURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("missing url")
	}

	target, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", target.Scheme)
	}

	hostname := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if hostname == "" {
		return nil, fmt.Errorf("missing host")
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".localhost") {
		return nil, fmt.Errorf("disallowed upstream host %q", hostname)
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if IsDisallowedIP(ip) {
			return nil, fmt.Errorf("disallowed upstream IP %q", ip.String())
		}
		return target, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if IsDisallowedIP(ip) {
			return nil, fmt.Errorf("disallowed upstream IP %q for host %q", ip.String(), hostname)
		}
	}

	return target, nil
}

// RedactURL returns a loggable form of a URL with userinfo and query stripped,
// since upstream subscription URLs embed secret tokens in those positions.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	redacted := *u
	redacted.User = nil
	if redacted.RawQuery != "" {
		redacted.RawQuery = "REDACTED"
	}
	redacted.Fragment = ""
	return redacted.String()
}
