package clash

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/frezcirno/cctools/internal/cache"
)

const goodUpstream = "proxies:\n  - {name: node-a, type: ss, server: a.example, port: 1, cipher: aes-128-gcm, password: x}\n"

const challengePage = `<!doctype html><html lang="en"><head><title>Making sure you&#39;re not a bot!</title>
<style>
        body,
        html {
            height: 100%;
        }
</style></head><body></body></html>`

type downloadCall struct {
	cacheKey      string
	useCacheOnErr bool
}

func stubUpstreamDownload(t *testing.T, body string, err error) *[]downloadCall {
	t.Helper()
	calls := []downloadCall{}
	original := downloadFn
	downloadFn = func(_ *url.URL, cacheKey string, _ time.Duration, _ int, useCacheOnErr, _ bool) ([]byte, error) {
		calls = append(calls, downloadCall{cacheKey, useCacheOnErr})
		if err != nil {
			return nil, err
		}
		return []byte(body), nil
	}
	t.Cleanup(func() { downloadFn = original })
	return &calls
}

func seedUpstreamCache(t *testing.T, key, body string, age time.Duration) time.Time {
	t.Helper()
	if err := cache.Save(key, []byte(body)); err != nil {
		t.Fatalf("cache.Save() error = %v", err)
	}
	t.Cleanup(func() { os.Remove("./cache/" + key) })
	stamp := time.Now().Add(-age).Truncate(time.Second)
	if err := os.Chtimes("./cache/"+key, stamp, stamp); err != nil {
		t.Fatalf("os.Chtimes() error = %v", err)
	}
	return stamp
}

func mustURL(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://sub.example/api?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestDownloadUpstreamSavesUnderTheAirportKey(t *testing.T) {
	key := "upstream-unit-save-0.yaml"
	t.Cleanup(func() { os.Remove("./cache/" + key) })
	calls := stubUpstreamDownload(t, goodUpstream, nil)

	airport, err := downloadUpstream(mustURL(t), key, 3600, 5, true)
	if err != nil {
		t.Fatalf("downloadUpstream() error = %v", err)
	}
	if airport.Proxies.Len() != 1 {
		t.Fatalf("proxies = %d, want 1", airport.Proxies.Len())
	}
	if saved, _ := cache.Load(key); string(saved) != goodUpstream {
		t.Fatalf("cache %s = %q, want the fetched body", key, saved)
	}
	// The fallback is owned by downloadUpstream, so Download must not run its
	// own (which used to read a different key).
	if len(*calls) != 1 || (*calls)[0].useCacheOnErr {
		t.Fatalf("download calls = %+v, want one call with useCacheOnErr=false", *calls)
	}
}

// Both failure modes — a transport/HTTP error and a 200 that isn't a config —
// must fall back to the same cache entry, and must not refresh its mtime.
func TestDownloadUpstreamFallsBackToOneKeyWithoutRefreshingIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		err  error
	}{
		{"http error", "", errors.New("unexpected HTTP status: 403 Forbidden")},
		{"html challenge", challengePage, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "upstream-unit-fallback-0.yaml"
			stamp := seedUpstreamCache(t, key, goodUpstream, 2*time.Hour)
			stubUpstreamDownload(t, tc.body, tc.err)

			airport, err := downloadUpstream(mustURL(t), key, 999999999, 5, true)
			if err != nil {
				t.Fatalf("downloadUpstream() error = %v, want the cached airport", err)
			}
			if airport.Proxies.Len() != 1 {
				t.Fatalf("proxies = %d, want the 1 cached node", airport.Proxies.Len())
			}
			modTime, err := cache.ModTime(key)
			if err != nil {
				t.Fatalf("cache.ModTime() error = %v", err)
			}
			if !modTime.Equal(stamp) {
				t.Fatalf("cache mtime = %v, want it left at %v so staleness stays visible", modTime, stamp)
			}
		})
	}
}

func TestDownloadUpstreamWithoutFallbackReturnsTheError(t *testing.T) {
	key := "upstream-unit-nofallback-0.yaml"
	seedUpstreamCache(t, key, goodUpstream, time.Hour)
	stubUpstreamDownload(t, challengePage, nil)

	if _, err := downloadUpstream(mustURL(t), key, 999999999, 5, false); err == nil {
		t.Fatal("downloadUpstream() error = nil, want an error when use-cache-on-err is off")
	}
}

func TestDescribeUnusableUpstreamNamesHTMLPages(t *testing.T) {
	err := describeUnusableUpstream([]byte(challengePage), errors.New("yaml: line 4: mapping values are not allowed"))
	msg := err.Error()
	for _, want := range []string{"HTML page", "Making sure you're not a bot!", "reauthoriz", "line 4"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}

	plain := describeUnusableUpstream([]byte("proxies: 3"), errors.New("proxies not found")).Error()
	if strings.Contains(plain, "HTML") {
		t.Errorf("non-HTML body described as HTML: %q", plain)
	}
}
