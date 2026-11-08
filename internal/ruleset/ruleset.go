// Package ruleset retrieves a Clash rule-provider body from the URL declared in
// the template.
//
// Template entries come in two forms: an absolute URL to a ready-made
// rule-provider YAML, or the relative "/convert?url=<raw list>" form, which
// names this server's own /convert endpoint. The relative form is resolved
// **in-process** — fetching it over HTTP would make the server call itself,
// which safehttp refuses whenever it is bound to a loopback or private address
// (the default). Handling it here also saves a round trip.
package ruleset

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net/url"
	"time"

	"github.com/frezcirno/cctools/internal/cache"
	"github.com/frezcirno/cctools/internal/fetch"
	"github.com/frezcirno/cctools/internal/safehttp"
)

// ConvertPath is the endpoint the relative template URLs point at.
const ConvertPath = "/convert"

const (
	// DefaultTTL is how long a fetched rule-provider body is served without
	// re-downloading. Both the /rule-providers endpoint and inline mode use it.
	DefaultTTL = 24 * time.Hour
	// DefaultTimeout (seconds) bounds one download. The largest lists in the
	// default template are several MB, so 10s was not enough on an ordinary link.
	DefaultTimeout = 60
)

// anyAge accepts a cache entry however old it is. It is only used for the
// failure fallback; going through cache.IsOK keeps DISABLE_CACHE and the
// future-mtime guard in force.
const anyAge = time.Duration(math.MaxInt64)

// staleFallback serves the last good copy when a refresh fails, regardless of
// its age. Freshness (the ttl) and fallback must stay separate: when the
// fallback was bounded by the ttl, the only way to keep it working was an
// enormous ttl, and then lists were never refreshed at all.
func staleFallback(cacheKey string, fetchErr error) ([]byte, error) {
	if ok, _ := cache.IsOK(cacheKey, anyAge); ok {
		if cached, err := cache.Load(cacheKey); err == nil {
			log.Printf("Refreshing %s failed, serving the stale cached copy: %v", cacheKey, fetchErr)
			return cached, nil
		}
	}
	return nil, fetchErr
}

// download is a seam: tests swap it so they can exercise the conversion path
// without a reachable, publicly-routable upstream.
var download = fetch.Download

// Fetch returns the rule-provider YAML for a template `url` value. cacheKey is
// where the *converted* body is cached, so a later upstream failure can fall
// back to it.
func Fetch(rawURL string, cacheKey string, ttl time.Duration, timeout int) ([]byte, error) {
	// A cache entry within its TTL is authoritative. fetch.Download treats the
	// cache purely as an error fallback, so without this check every request
	// re-downloaded all 21 providers — tens of MB — which is what pushed config
	// generation past the server's WriteTimeout.
	if ok, _ := cache.IsOK(cacheKey, ttl); ok {
		if cached, err := cache.Load(cacheKey); err == nil {
			return cached, nil
		}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid rule-provider url %q: %w", rawURL, err)
	}

	if parsed.IsAbs() {
		body, err := download(parsed, cacheKey, ttl, timeout, false, false)
		if err != nil {
			return staleFallback(cacheKey, err)
		}
		if err := cache.Save(cacheKey, body); err != nil {
			return nil, err
		}
		return body, nil
	}

	if parsed.Path != ConvertPath {
		return nil, fmt.Errorf("unsupported relative rule-provider url %q", rawURL)
	}
	return fetchConverted(parsed.Query().Get("url"), cacheKey, ttl, timeout)
}

// fetchConverted downloads a raw rule list and wraps it as a rule-provider,
// doing locally what a request to /convert would have done remotely.
func fetchConverted(target string, cacheKey string, ttl time.Duration, timeout int) ([]byte, error) {
	listURL, err := safehttp.ValidateUpstreamURL(target)
	if err != nil {
		return nil, fmt.Errorf("rule-provider convert target: %w", err)
	}

	// useCacheOnErr is false here: cacheKey holds the *converted* body, so
	// letting Download return it would feed already-wrapped YAML back through
	// ConvertRawList. The fallback is done explicitly below instead.
	raw, err := download(listURL, "", ttl, timeout, false, false)
	if err != nil {
		return staleFallback(cacheKey, err)
	}

	converted, hasRules := ConvertRawList(raw)
	if hasRules {
		// Don't cache degenerate (empty / comment-only) conversions: a transient
		// empty upstream response would otherwise poison the cache.
		if err := cache.Save(cacheKey, converted); err != nil {
			return nil, err
		}
	}
	return converted, nil
}

// ConvertRawList turns a raw newline-delimited rule list into a Clash
// rule-provider document under a top-level `payload:` key. It always emits a
// valid `payload:` mapping (an empty list when there are no rules), so a
// transiently empty or comment-only upstream cannot produce invalid YAML. The
// returned bool reports whether any actual rule was present (used to avoid
// caching degenerate output).
func ConvertRawList(rawList []byte) ([]byte, bool) {
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
