package cache

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

var keySeq atomic.Int64

func testKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test_%s_%d", t.Name(), keySeq.Add(1))
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	key := testKey(t)
	content := []byte("hello cache")

	if err := Save(key, content); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	defer os.Remove(path(key))

	loaded, err := Load(key)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(loaded) != string(content) {
		t.Fatalf("Load() = %q, want %q", loaded, content)
	}
}

func TestCacheIsOkRespectsTTL(t *testing.T) {
	key := testKey(t)

	if err := Save(key, []byte("data")); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	defer os.Remove(path(key))

	ok, _ := IsOK(key, 1*time.Hour)
	if !ok {
		t.Fatal("IsOK should return true for fresh cache with long TTL")
	}

	ok, _ = IsOK(key, 0)
	if ok {
		t.Fatal("IsOK should return false for TTL=0")
	}
}

func TestCacheIsOkReturnsFalseForMissing(t *testing.T) {
	ok, err := IsOK(testKey(t), 1*time.Hour)
	if ok {
		t.Fatal("IsOK should return false for missing key")
	}
	if err == nil {
		t.Fatal("IsOK should return error for missing key")
	}
}

// TestCacheDisabledBypassesReadsAndWrites guards that DISABLE_CACHE skips both
// halves of the cache, not just writes.
func TestCacheDisabledBypassesReadsAndWrites(t *testing.T) {
	key := testKey(t)
	if err := Save(key, []byte("data")); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	defer os.Remove(path(key))

	t.Setenv("DISABLE_CACHE", "1")

	if ok, _ := IsOK(key, 1*time.Hour); ok {
		t.Fatal("IsOK should return false when DISABLE_CACHE is set")
	}
	if err := Save(testKey(t), []byte("data")); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
}
