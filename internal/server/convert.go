package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/frezcirno/cctools/internal/cache"
	"github.com/frezcirno/cctools/internal/ruleset"
	"github.com/frezcirno/cctools/internal/safehttp"
)

// handleRuleProviders serves a template rule-provider by name, used by the
// "proxy" rule_provider_transform mode.
func (s *Server) handleRuleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ruleSetName := r.URL.Query().Get("rule-set")
	if ruleSetName == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	template, err := loadTemplate()
	if err != nil {
		log.Printf("Failed to load template: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ruleProviders, ok := template["rule-providers"].(map[string]any)
	if !ok {
		log.Printf("Failed to load rule-providers\n")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ruleProvider, ok := ruleProviders[ruleSetName].(map[string]any)
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	ruleURL, ok := ruleProvider["url"].(string)
	if !ok {
		log.Printf("rule-provider %q has no url\n", ruleSetName)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Rule-provider URLs are fetched at request time: only http/https (no
	// local-file reads), and the relative "/convert?url=…" form is expanded
	// in-process rather than by looping back through our own endpoint.
	content, err := ruleset.Fetch(ruleURL, fmt.Sprintf("rule-%s.yaml", ruleSetName), 5*365*24*time.Hour, 10)
	if err != nil {
		log.Printf("Failed to download rule-provider %s: %v\n", ruleSetName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(content)
}

// makeConvertProxy builds the /convert reverse proxy: it fetches a raw rule
// list from an arbitrary (validated) upstream and rewrites it into Clash
// `payload:` YAML, caching the result for 24h.
func (s *Server) makeConvertProxy() http.Handler {
	revProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "baidu.com",
	})

	revProxy.Director = func(req *http.Request) {
		logRequest(req)

		upstreamURL, err := safehttp.ValidateUpstreamURL(req.URL.Query().Get("url"))
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

	// safehttp.Transport re-validates the resolved IP at dial time, so this also
	// rejects DNS-rebinding to internal addresses, not just the pre-flight
	// hostname check done in the Director.
	revProxy.Transport = safehttp.Transport

	revProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	revProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(io.LimitReader(resp.Body, safehttp.MaxResponseBytes+1)); err != nil {
			return err
		}
		if int64(buf.Len()) > safehttp.MaxResponseBytes {
			return fmt.Errorf("/convert upstream response exceeds %d bytes", safehttp.MaxResponseBytes)
		}

		converted, hasRules := ruleset.ConvertRawList(buf.Bytes())

		// Don't cache degenerate (empty / comment-only) conversions: a transient
		// empty upstream response would otherwise poison the cache for 24h.
		if hasRules && resp.Request != nil && resp.Request.URL != nil {
			if err := cache.Save(cache.Key(resp.Request.URL), converted); err != nil {
				log.Printf("Failed to save /convert cache for %s: %v", safehttp.RedactURL(resp.Request.URL), err)
			}
		}

		resp.Body = io.NopCloser(bytes.NewReader(converted))
		resp.ContentLength = int64(len(converted))
		resp.Header["Content-Length"] = []string{fmt.Sprint(len(converted))}
		resp.Header.Set("Content-Type", "application/x-yaml")

		return nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamURL, err := safehttp.ValidateUpstreamURL(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cacheKey := cache.Key(upstreamURL)
		const ttl = 24 * time.Hour
		if ok, _ := cache.IsOK(cacheKey, ttl); ok {
			if content, err := cache.Load(cacheKey); err == nil {
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
