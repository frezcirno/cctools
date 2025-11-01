package main

import (
	"crypto/sha1"
	"fmt"
	"net/url"
	"os"
	"time"
)

func make_cache_key(url *url.URL) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(url.String())))
}

func load_cache(cache_key string) ([]byte, error) {
	save_path := "./cache/" + cache_key
	return fsLoad(save_path)
}

func save_cache(cache_key string, content []byte) error {
	if _, err := os.LookupEnv("DISABLE_CACHE"); !err {
		return nil
	}

	os.MkdirAll("./cache", os.ModePerm)

	save_path := "./cache/" + cache_key
	if f, err := os.Create(save_path); err == nil {
		defer f.Close()
		f.Write(content)
	}

	return nil
}

func cache_is_ok(cache_key string, ttl time.Duration) (bool, error) {
	save_path := "./cache/" + cache_key

	fi, err := fsStat(save_path)
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
