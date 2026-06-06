package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes caps how much we will buffer from any single upstream /
// rule-provider response, to bound memory use against hostile or huge bodies.
const maxResponseBytes = 32 << 20 // 32 MiB

func download(url *url.URL,
	cache_key string,
	ttl time.Duration,
	timeout int,
	use_cache_on_err bool,
	allowLocalSchemes bool,
) ([]byte, error) {
	if cache_key == "" {
		cache_key = make_cache_key(url)
	}
	cache_ok, _ := cache_is_ok(cache_key, ttl)

	log.Printf("Retrieving %s, cache: %s, ttl: %d, use-cache-on-err: %v, cache-ok: %v", redactURL(url), cache_key, ttl, use_cache_on_err, cache_ok)

	var content []byte

	switch url.Scheme {
	case "file":
		if !allowLocalSchemes {
			return nil, fmt.Errorf("scheme %q not allowed for this request", url.Scheme)
		}
		var err error
		if content, err = fsLoad(url.Path); err != nil {
			if cache_ok && use_cache_on_err {
				return load_cache(cache_key)
			}
			return nil, err
		}
	case "base64":
		if !allowLocalSchemes {
			return nil, fmt.Errorf("scheme %q not allowed for this request", url.Scheme)
		}
		var err error
		content, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(url.Host)))
		if err != nil {
			if cache_ok && use_cache_on_err {
				return load_cache(cache_key)
			}
			return nil, err
		}
	case "http", "https":
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
		if err != nil {
			log.Printf("Failed to request %s: %v", redactURL(url), err)
			return nil, err
		}

		req.Header = http.Header{
			"User-Agent":                []string{USER_AGENT},
			"Accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"Cache-Control":             []string{"no-cache"},
			"Pragma":                    []string{"no-cache"},
			"Accept-Language":           []string{"zh-CN,zh;q=0.9"},
			"Sec-Fetch-Dest":            []string{"document"},
			"Sec-Fetch-Mode":            []string{"navigate"},
			"Sec-Fetch-Site":            []string{"none"},
			"Sec-Fetch-User":            []string{"?1"},
			"Upgrade-Insecure-Requests": []string{"1"},
			"sec-ch-ua":                 []string{"\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\""},
			"sec-ch-ua-mobile":          []string{"?0"},
			"sec-ch-ua-platform":        []string{"\"Windows\""},
		}
		resp, err := safeHTTPClient.Do(req)
		if err != nil {
			if cache_ok && use_cache_on_err {
				return load_cache(cache_key)
			}
			log.Printf("Failed to request %s: %v", redactURL(url), err)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected HTTP status for %s: %s", redactURL(url), resp.Status)
			if cache_ok && use_cache_on_err {
				return load_cache(cache_key)
			}
			log.Printf("Failed to request %s: %v", redactURL(url), err)
			return nil, err
		}

		content, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		if err != nil {
			if cache_ok && use_cache_on_err {
				return load_cache(cache_key)
			}
			return nil, err
		}
		if int64(len(content)) > maxResponseBytes {
			return nil, fmt.Errorf("response from %s exceeds %d bytes", redactURL(url), maxResponseBytes)
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", url.Scheme)
	}

	return content, nil
}

// redactURL returns a loggable form of a URL with userinfo and query stripped,
// since upstream subscription URLs embed secret tokens in those positions.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	redacted := *u
	redacted.User = nil
	if redacted.RawQuery != "" {
		redacted.RawQuery = "REDACTED"
	}
	redacted.Fragment = ""
	return redacted.String()
}
