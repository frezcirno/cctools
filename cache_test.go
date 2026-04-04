package main

import (
	"os"
	"testing"
	"time"
)

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	os.MkdirAll("./cache", os.ModePerm)
	key := "test_roundtrip_" + randomStr(8)
	content := []byte("hello cache")

	if err := save_cache(key, content); err != nil {
		t.Fatalf("save_cache() error = %v", err)
	}

	loaded, err := load_cache(key)
	if err != nil {
		t.Fatalf("load_cache() error = %v", err)
	}
	if string(loaded) != string(content) {
		t.Fatalf("load_cache() = %q, want %q", loaded, content)
	}

	// Cleanup
	os.Remove("./cache/" + key)
}

func TestCacheIsOkRespectsTTL(t *testing.T) {
	os.MkdirAll("./cache", os.ModePerm)
	key := "test_ttl_" + randomStr(8)

	if err := save_cache(key, []byte("data")); err != nil {
		t.Fatalf("save_cache() error = %v", err)
	}

	ok, _ := cache_is_ok(key, 1*time.Hour)
	if !ok {
		t.Fatal("cache_is_ok should return true for fresh cache with long TTL")
	}

	ok, _ = cache_is_ok(key, 0)
	if ok {
		t.Fatal("cache_is_ok should return false for TTL=0")
	}

	// Cleanup
	os.Remove("./cache/" + key)
}

func TestCacheIsOkReturnsFalseForMissing(t *testing.T) {
	ok, err := cache_is_ok("nonexistent_key_"+randomStr(8), 1*time.Hour)
	if ok {
		t.Fatal("cache_is_ok should return false for missing key")
	}
	if err == nil {
		t.Fatal("cache_is_ok should return error for missing key")
	}
}
