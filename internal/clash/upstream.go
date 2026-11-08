package clash

import (
	"bytes"
	"fmt"
	"html"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/frezcirno/cctools/internal/cache"
	"github.com/frezcirno/cctools/internal/fetch"
	"github.com/frezcirno/cctools/internal/safehttp"
)

// downloadFn is the network seam, swapped out in tests.
var downloadFn = fetch.Download

// downloadUpstream fetches and parses one subscription URL. cacheKey names this
// airport's last good copy (upstream-<name>-<idx>.yaml).
//
// The cache fallback lives here and only here, under that one key. It used to
// be split: fetch.Download fell back to cacheKey on a transport error, while a
// parse error fell back to sha1(url), which is also where successes were
// saved. So a failing upstream could serve either last hour's nodes or a
// months-old snapshot depending on how it failed, and the fallback copy was
// re-saved as if fresh, hiding how old it was.
func downloadUpstream(upstream *url.URL, cacheKey string, ttlSec int, timeout int, useCacheOnErr bool) (*Airport, error) {
	ttl := time.Duration(ttlSec) * time.Second
	redacted := safehttp.RedactURL(upstream)

	// Upstreams may legitimately use file:// / base64:// (operator-configured,
	// token-gated), so local schemes are allowed here.
	content, err := downloadFn(upstream, cacheKey, ttl, timeout, false, true)
	if err == nil {
		airport, parseErr := parseUpstream(content)
		if parseErr == nil {
			cache.Save(cacheKey, content)
			return airport, nil
		}
		err = describeUnusableUpstream(content, parseErr)
	}
	log.Printf("Upstream %v failed: %v", redacted, err)

	if !useCacheOnErr {
		return nil, err
	}
	if ok, _ := cache.IsOK(cacheKey, ttl); !ok {
		return nil, err
	}
	cached, loadErr := cache.Load(cacheKey)
	if loadErr != nil {
		return nil, err
	}
	airport, parseErr := parseUpstream(cached)
	if parseErr != nil {
		log.Printf("Cached copy %s of upstream %v is unusable too: %v", cacheKey, redacted, parseErr)
		return nil, err
	}
	// Deliberately not re-saved: the cache mtime must keep saying when this
	// upstream last really worked.
	savedAt := "unknown time"
	if modTime, statErr := cache.ModTime(cacheKey); statErr == nil {
		savedAt = fmt.Sprintf("%s, %s ago", modTime.Format(time.RFC3339), time.Since(modTime).Round(time.Minute))
	}
	log.Printf("WARNING: serving STALE upstream %v from cache %s (saved %s) because the live fetch failed", redacted, cacheKey, savedAt)
	return airport, nil
}

var htmlTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// describeUnusableUpstream explains a 200 response that isn't a Clash config.
// The usual culprit is an HTML page — a login, an anti-bot challenge, an
// expired-token notice — which YAML reports only as e.g. "line 4: mapping
// values are not allowed".
func describeUnusableUpstream(content []byte, parseErr error) error {
	head := bytes.ToLower(bytes.TrimSpace(content))
	if len(head) > 512 {
		head = head[:512]
	}
	if bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html")) || bytes.Contains(head, []byte("<head")) {
		title := ""
		if m := htmlTitle.FindSubmatch(content); m != nil {
			title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
		}
		return fmt.Errorf("upstream returned an HTML page (title %q) instead of a Clash config; the subscription link may need reauthorizing in a browser: %w", title, parseErr)
	}
	return fmt.Errorf("upstream response is not a usable Clash config: %w", parseErr)
}

func parseUpstream(content []byte) (*Airport, error) {
	var obj YamlStrDict
	if err := yaml.Unmarshal(content, &obj); err != nil {
		return nil, err
	}

	proxyRaw, err := asAnyList(obj["proxies"], "proxies")
	if err != nil {
		return nil, fmt.Errorf("proxies not found")
	}
	proxies, err := NewDictList(proxyRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxies: %w", err)
	}

	airport := Airport{Proxies: proxies}

	airport.filterProxy(func(m YamlStrDict) bool {
		for _, b := range PROXY_BLACKLIST {
			if _, ok := m["name"]; ok {
				if strings.Contains(m["name"].(string), b) {
					return false
				}
			}
		}
		return true
	})

	return &airport, nil
}
