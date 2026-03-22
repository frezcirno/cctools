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
	"time"
)

func convertRawListToRuleProvider(rawList []byte) []byte {
	rules := make([][]byte, 0)
	lines := bytes.Split(rawList, []byte("\n"))

	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || bytes.HasPrefix(l, []byte("#")) {
			rules = append(rules, l)
		} else {
			rules = append(rules, []byte(" - "+string(l)))
		}
	}

	for i := range rules {
		if bytes.HasPrefix(rules[i], []byte(" - ")) {
			rules = append(rules[:i], append([][]byte{[]byte("payload:")}, rules[i:]...)...)
			break
		}
	}

	return bytes.Join(rules, []byte("\n"))
}

func isDisallowedUpstreamIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
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

	rule_providers, ok := template["rule-providers"].(map[any]any)
	if !ok {
		log.Printf("Failed to load rule-providers: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rule_provider, ok := rule_providers[rule_set_name].(map[any]any)
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

	content, err := download(parsedURL, fmt.Sprintf("rule-%s.yaml", rule_set_name), 5*365*24*time.Hour, 10, true)
	if err != nil {
		log.Printf("Failed to download rule-provider: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(content)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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

	revProxy.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if _, err := validateProxyUpstream(req.URL.String()); err != nil {
			return nil, err
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	revProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)

		b := buf.Bytes()
		newb := convertRawListToRuleProvider(b)
		newbuf := bytes.NewBuffer(newb)

		if resp.Request != nil && resp.Request.URL != nil {
			cacheKey := make_cache_key(resp.Request.URL)
			if err := save_cache(cacheKey, newb); err != nil {
				log.Printf("Failed to save /convert cache for %s: %v", resp.Request.URL.String(), err)
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
