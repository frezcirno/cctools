package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// convertRawListToRuleProvider turns a raw newline-delimited rule list into a
// Clash rule-provider document under a top-level `payload:` key. It always emits
// a valid `payload:` mapping (an empty list when there are no rules), so a
// transiently empty or comment-only upstream cannot produce invalid YAML. The
// returned bool reports whether any actual rule was present (used to avoid
// caching degenerate output).
func convertRawListToRuleProvider(rawList []byte) ([]byte, bool) {
	rules := make([][]byte, 0)
	lines := bytes.Split(rawList, []byte("\n"))

	hasRule := false
	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || bytes.HasPrefix(l, []byte("#")) {
			rules = append(rules, l)
		} else {
			rules = append(rules, []byte(" - "+string(l)))
			hasRule = true
		}
	}

	if !hasRule {
		// No rules: emit a valid empty payload, preserving any leading comments.
		rules = append(rules, []byte("payload: []"))
		return bytes.Join(rules, []byte("\n")), false
	}

	for i := range rules {
		if bytes.HasPrefix(rules[i], []byte(" - ")) {
			rules = append(rules[:i], append([][]byte{[]byte("payload:")}, rules[i:]...)...)
			break
		}
	}

	return bytes.Join(rules, []byte("\n")), true
}

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

func isDisallowedUpstreamIP(ip net.IP) bool {
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

// safeDialer rejects connections to disallowed IPs at dial time — after DNS
// resolution, on the actual address about to be connected. This closes the
// TOCTOU / DNS-rebinding gap that a pre-flight net.LookupIP check leaves open,
// and (because it runs for every connection) also re-validates redirect hops.
var safeDialer = &net.Dialer{
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
		if isDisallowedUpstreamIP(ip) {
			return fmt.Errorf("disallowed dial IP %s", ip)
		}
		return nil
	},
}

var safeTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           safeDialer.DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// safeHTTPClient is the shared client for all outbound fetches of untrusted
// URLs (upstreams and rule-providers). Redirects are followed but every hop is
// re-validated by safeDialer.Control.
var safeHTTPClient = &http.Client{
	Transport: safeTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	},
}

func validateProxyUpstream(raw string) (*url.URL, error) {
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
		if isDisallowedUpstreamIP(ip) {
			return nil, fmt.Errorf("disallowed upstream IP %q", ip.String())
		}
		return target, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if isDisallowedUpstreamIP(ip) {
			return nil, fmt.Errorf("disallowed upstream IP %q for host %q", ip.String(), hostname)
		}
	}

	return target, nil
}

func handleRuleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	rule_set_name := query.Get("rule-set")
	if rule_set_name == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	template, err := loadTemplate()
	if err != nil {
		log.Printf("Failed to load template: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rule_providers, ok := template["rule-providers"].(map[string]any)
	if !ok {
		log.Printf("Failed to load rule-providers\n")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rule_provider, ok := rule_providers[rule_set_name].(map[string]any)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	ruleURL, ok := rule_provider["url"].(string)
	if !ok {
		log.Printf("Failed to load rule-provider url: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	parsedURL, err := url.Parse(ruleURL)
	if err != nil {
		log.Printf("Failed to parse rule-provider url: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	content, err := download(parsedURL, fmt.Sprintf("rule-%s.yaml", rule_set_name), 5*365*24*time.Hour, 10, true, false)
	if err != nil {
		log.Printf("Failed to download rule-provider: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(content)
}

func makeProxy() http.Handler {
	revProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "baidu.com",
	})

	revProxy.Director = func(req *http.Request) {
		logRequest(req)

		upstreamURL, err := validateProxyUpstream(req.URL.Query().Get("url"))
		if err != nil {
			log.Printf("Rejected /convert upstream: %v", err)
			req.URL = &url.URL{}
			req.Host = ""
			req.Header.Del("Host")
			return
		}

		req.URL = upstreamURL
		req.Host = upstreamURL.Host
		req.Header["Host"] = []string{upstreamURL.Host}
		req.Header["X-Forwarded-For"] = nil
		req.Header["Accept-Encoding"] = nil
	}

	// safeTransport re-validates the resolved IP at dial time (see safeDialer),
	// so this also rejects DNS-rebinding to internal addresses, not just the
	// pre-flight hostname check done in the Director.
	revProxy.Transport = safeTransport

	revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	revProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(io.LimitReader(resp.Body, maxResponseBytes+1)); err != nil {
			return err
		}
		if int64(buf.Len()) > maxResponseBytes {
			return fmt.Errorf("/convert upstream response exceeds %d bytes", maxResponseBytes)
		}

		b := buf.Bytes()
		newb, hasRules := convertRawListToRuleProvider(b)
		newbuf := bytes.NewBuffer(newb)

		// Don't cache degenerate (empty / comment-only) conversions: a transient
		// empty upstream response would otherwise poison the cache for 24h.
		if hasRules && resp.Request != nil && resp.Request.URL != nil {
			cacheKey := make_cache_key(resp.Request.URL)
			if err := save_cache(cacheKey, newb); err != nil {
				log.Printf("Failed to save /convert cache for %s: %v", redactURL(resp.Request.URL), err)
			}
		}

		resp.Body = io.NopCloser(newbuf)
		resp.ContentLength = int64(newbuf.Len())
		resp.Header["Content-Length"] = []string{fmt.Sprint(newbuf.Len())}
		resp.Header.Set("Content-Type", "application/x-yaml")

		return nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamURL, err := validateProxyUpstream(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cacheKey := make_cache_key(upstreamURL)
		const ttl = 24 * time.Hour
		if ok, _ := cache_is_ok(cacheKey, ttl); ok {
			if content, err := load_cache(cacheKey); err == nil {
				w.Header().Set("Content-Type", "application/x-yaml")
				w.Header().Set("X-Cache", "HIT")
				w.Write(content)
				return
			}
		}

		w.Header().Set("X-Cache", "MISS")
		revProxy.ServeHTTP(w, r)
	})
}
