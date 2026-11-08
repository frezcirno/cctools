package ruleset

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/frezcirno/cctools/internal/cache"
)

// stubDownload swaps the download seam for the duration of a test.
func stubDownload(t *testing.T, body []byte, err error) *string {
	t.Helper()
	var got string
	original := download
	download = func(u *url.URL, _ string, _ time.Duration, _ int, _, _ bool) ([]byte, error) {
		got = u.String()
		return body, err
	}
	t.Cleanup(func() { download = original })
	return &got
}

func TestConvertRawList(t *testing.T) {
	withRules, has := ConvertRawList([]byte("DOMAIN,example.com\n# a comment\nIP-CIDR,1.1.1.0/24\n"))
	if !has {
		t.Fatal("expected hasRules=true")
	}
	if !bytes.Contains(withRules, []byte("payload:")) || !bytes.Contains(withRules, []byte(" - DOMAIN,example.com")) {
		t.Fatalf("expected payload + rule lines, got:\n%s", withRules)
	}

	// Comment-only and empty inputs must still produce a valid payload mapping.
	for _, in := range []string{"# only a comment\n\n", ""} {
		out, has := ConvertRawList([]byte(in))
		if has {
			t.Errorf("input %q: expected hasRules=false", in)
		}
		if !bytes.Contains(out, []byte("payload: []")) {
			t.Errorf("input %q: expected 'payload: []', got:\n%s", in, out)
		}
	}
}

// TestFetchConvertsRelativeURLInProcess is the regression guard for the 500 that
// inline/proxy mode used to return: a "/convert?url=…" template entry was
// resolved against this server and fetched over HTTP, which safehttp refuses
// whenever the server is bound to loopback (the default). The fetch must go
// straight to the raw list instead.
func TestFetchConvertsRelativeURLInProcess(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	fetched := stubDownload(t, []byte("DOMAIN-SUFFIX,example.com\n# comment\nIP-CIDR,1.1.1.0/24\n"), nil)

	body, err := Fetch(ConvertPath+"?url=http://8.8.8.8/list.txt", "rule-test.yaml", time.Hour, 10)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if *fetched != "http://8.8.8.8/list.txt" {
		t.Fatalf("downloaded %q, want the raw list URL — not a self-request to /convert", *fetched)
	}
	if !bytes.Contains(body, []byte("payload:")) || !bytes.Contains(body, []byte(" - DOMAIN-SUFFIX,example.com")) {
		t.Fatalf("body was not converted to a rule-provider:\n%s", body)
	}
}

func TestFetchPassesAbsoluteURLThrough(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	raw := []byte("payload:\n  - DOMAIN,example.com\n")
	fetched := stubDownload(t, raw, nil)

	body, err := Fetch("https://example.com/rules.yaml", "rule-test.yaml", time.Hour, 10)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if *fetched != "https://example.com/rules.yaml" {
		t.Fatalf("downloaded %q, want the absolute URL unchanged", *fetched)
	}
	// An absolute URL already points at a rule-provider: it must not be run
	// through ConvertRawList, which would wrap the payload a second time.
	if !bytes.Equal(body, raw) {
		t.Fatalf("absolute URL body was rewritten:\n%s", body)
	}
}

// TestFetchServesFreshCacheWithoutDownloading guards the cost fix: a cache
// entry inside its TTL must short-circuit the download, or every request
// re-fetches tens of MB of rule lists.
func TestFetchServesFreshCacheWithoutDownloading(t *testing.T) {
	key := "rule-cachehit-test.yaml"
	body := []byte("payload:\n  - DOMAIN,cached.example\n")
	if err := cache.Save(key, body); err != nil {
		t.Fatalf("cache.Save() error = %v", err)
	}
	t.Cleanup(func() { os.Remove("./cache/" + key) })

	downloaded := stubDownload(t, []byte("payload: []"), nil)

	got, err := Fetch("https://example.com/rules.yaml", key, time.Hour, 10)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if *downloaded != "" {
		t.Fatalf("downloaded %q, want no download at all on a fresh cache hit", *downloaded)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("Fetch() = %q, want the cached body %q", got, body)
	}
}

func TestFetchRejectsUnsupportedRelativeURL(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	_, err := Fetch("/somewhere-else?x=1", "rule-test.yaml", time.Hour, 10)
	if err == nil || !strings.Contains(err.Error(), "unsupported relative") {
		t.Fatalf("Fetch() error = %v, want an 'unsupported relative' error", err)
	}
}

// TestFetchRejectsBlockedConvertTarget checks the SSRF guard still applies to
// the target extracted from the query string.
func TestFetchRejectsBlockedConvertTarget(t *testing.T) {
	t.Setenv("DISABLE_CACHE", "1")

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data", // cloud metadata
		"http://127.0.0.1/x",                      // loopback
		"file:///etc/passwd",                      // local file read
	} {
		if _, err := Fetch(ConvertPath+"?url="+target, "rule-test.yaml", time.Hour, 10); err == nil {
			t.Errorf("Fetch(%q) error = nil, want the SSRF guard to reject it", target)
		}
	}
}

// seedStaleCache writes a cache entry and backdates it well past any ttl the
// tests use, so it is expired but still present on disk.
func seedStaleCache(t *testing.T, key string, body []byte) {
	t.Helper()
	if err := cache.Save(key, body); err != nil {
		t.Fatalf("cache.Save() error = %v", err)
	}
	t.Cleanup(func() { os.Remove("./cache/" + key) })
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes("./cache/"+key, old, old); err != nil {
		t.Fatalf("os.Chtimes() error = %v", err)
	}
}

// Regression: /rule-providers used a 5-year ttl so the failure fallback would
// keep working, which meant a list cached once was never refreshed.
func TestFetchRefreshesExpiredCache(t *testing.T) {
	key := "rule-expired-refresh-test.yaml"
	seedStaleCache(t, key, []byte("payload:\n  - DOMAIN,old.example\n"))
	fresh := []byte("payload:\n  - DOMAIN,new.example\n")
	downloaded := stubDownload(t, fresh, nil)

	got, err := Fetch("https://example.com/rules.yaml", key, DefaultTTL, DefaultTimeout)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if *downloaded == "" {
		t.Fatal("expired cache was served without trying to refresh it")
	}
	if !bytes.Equal(got, fresh) {
		t.Fatalf("Fetch() = %q, want the fresh body %q", got, fresh)
	}
	if saved, _ := cache.Load(key); !bytes.Equal(saved, fresh) {
		t.Fatalf("cache holds %q after refresh, want %q", saved, fresh)
	}
}

func TestFetchFallsBackToStaleCacheWhenRefreshFails(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"absolute", "https://example.com/rules.yaml"},
		{"converted", ConvertPath + "?url=" + url.QueryEscape("https://example.com/list.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "rule-stale-fallback-" + tc.name + "-test.yaml"
			stale := []byte("payload:\n  - DOMAIN,stale.example\n")
			seedStaleCache(t, key, stale)
			stubDownload(t, nil, errors.New("unexpected EOF"))

			got, err := Fetch(tc.url, key, DefaultTTL, DefaultTimeout)
			if err != nil {
				t.Fatalf("Fetch() error = %v, want the stale copy", err)
			}
			if !bytes.Equal(got, stale) {
				t.Fatalf("Fetch() = %q, want the stale body %q", got, stale)
			}
		})
	}
}

func TestFetchFailsWithoutAnyCache(t *testing.T) {
	stubDownload(t, nil, errors.New("unexpected EOF"))
	if _, err := Fetch("https://example.com/rules.yaml", "rule-no-cache-test.yaml", DefaultTTL, DefaultTimeout); err == nil {
		t.Fatal("Fetch() error = nil, want the download error when nothing is cached")
	}
}

func TestFetchStaleFallbackHonoursDisableCache(t *testing.T) {
	key := "rule-stale-disabled-test.yaml"
	seedStaleCache(t, key, []byte("payload:\n  - DOMAIN,stale.example\n"))
	stubDownload(t, nil, errors.New("unexpected EOF"))
	t.Setenv("DISABLE_CACHE", "1")

	if _, err := Fetch("https://example.com/rules.yaml", key, DefaultTTL, DefaultTimeout); err == nil {
		t.Fatal("Fetch() served a cached copy with DISABLE_CACHE set")
	}
}
