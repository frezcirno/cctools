package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	ruleUrl, ok := rule_provider["url"].(string)
	if !ok {
		log.Printf("Failed to load rule-provider url: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	url, err := url.Parse(ruleUrl)
	if err != nil {
		log.Printf("Failed to parse rule-provider url: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	content, err := download(url, fmt.Sprintf("rule-%s.yaml", rule_set_name), 5*365*24*time.Hour, nil, 10, true)
	if err != nil {
		log.Printf("Failed to download rule-provider: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(content)
}

func makeProxy() *httputil.ReverseProxy {
	revProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "baidu.com",
	})

	revProxy.Director = func(req *http.Request) {
		logRequest(req)

		upstream := req.URL.Query().Get("url")
		if upstream == "" {
			return
		}

		upstreamURL, err := url.Parse(upstream)
		if err != nil {
			return
		}

		req.URL = upstreamURL
		req.Host = upstreamURL.Host

		req.Header["Host"] = []string{upstreamURL.Host}
		req.Header["X-Forwarded-For"] = nil
		req.Header["Accept-Encoding"] = nil
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

		resp.Body = io.NopCloser(newbuf)
		resp.ContentLength = int64(newbuf.Len())
		resp.Header["Content-Length"] = []string{fmt.Sprint(newbuf.Len())}

		return nil
	}

	return revProxy
}
