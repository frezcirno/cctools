// Package cache stores downloaded upstream / rule-provider bodies on disk under
// ./cache, keyed by SHA1 of the source URL, with a caller-supplied TTL.
//
// Setting the DISABLE_CACHE environment variable bypasses the cache entirely:
// both writes and reads are skipped, so every request goes to the source.
package cache

import (
	"crypto/sha1"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/frezcirno/cctools/internal/vfs"
)

const dir = "./cache"

func disabled() bool {
	_, ok := os.LookupEnv("DISABLE_CACHE")
	return ok
}

func path(key string) string {
	return dir + "/" + key
}

// Key derives the cache key for a URL.
func Key(u *url.URL) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(u.String())))
}

// Load reads a cache entry. It does not check freshness — call IsOK first.
func Load(key string) ([]byte, error) {
	return vfs.Load(path(key))
}

// Save writes a cache entry, or does nothing when caching is disabled.
func Save(key string, content []byte) error {
	if disabled() {
		return nil
	}

	os.MkdirAll(dir, os.ModePerm)

	vfs.Store(path(key), content)
	return nil
}

// IsOK reports whether a cache entry exists and is younger than ttl.
func IsOK(key string, ttl time.Duration) (bool, error) {
	// When caching is disabled, never treat any cache entry as valid so reads
	// always go to the source (DISABLE_CACHE already skips writes).
	if disabled() {
		return false, nil
	}

	fi, err := vfs.Stat(path(key))
	if err != nil {
		return false, err
	}

	now := time.Now()
	ctime := fi.ModTime()
	if ctime.After(now) {
		// clock reverted
		return false, nil
	}

	if now.Sub(ctime) < ttl {
		return true, nil
	}

	// expired or ttl == 0
	return false, nil
}
