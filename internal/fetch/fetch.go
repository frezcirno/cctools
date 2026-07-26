// Package fetch retrieves the bodies behind upstream and rule-provider URLs,
// layering the on-disk cache over safehttp's IP-validating client.
package fetch

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

	"github.com/frezcirno/cctools/internal/cache"
	"github.com/frezcirno/cctools/internal/safehttp"
	"github.com/frezcirno/cctools/internal/vfs"
)

// UserAgent is sent with every outbound fetch; some subscription providers
// reject unrecognized clients.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Download retrieves u, optionally falling back to the cached copy on error.
//
// allowLocalSchemes enables file:// and base64:// — permitted only for
// operator-configured upstreams, never for request-time rule-provider URLs.
func Download(u *url.URL,
	cacheKey string,
	ttl time.Duration,
	timeout int,
	useCacheOnErr bool,
	allowLocalSchemes bool,
) ([]byte, error) {
	if cacheKey == "" {
		cacheKey = cache.Key(u)
	}
	cacheOK, _ := cache.IsOK(cacheKey, ttl)

	log.Printf("Retrieving %s, cache: %s, ttl: %d, use-cache-on-err: %v, cache-ok: %v", safehttp.RedactURL(u), cacheKey, ttl, useCacheOnErr, cacheOK)

	var content []byte

	switch u.Scheme {
	case "file":
		if !allowLocalSchemes {
			return nil, fmt.Errorf("scheme %q not allowed for this request", u.Scheme)
		}
		var err error
		if content, err = vfs.Load(u.Path); err != nil {
			if cacheOK && useCacheOnErr {
				return cache.Load(cacheKey)
			}
			return nil, err
		}
	case "base64":
		if !allowLocalSchemes {
			return nil, fmt.Errorf("scheme %q not allowed for this request", u.Scheme)
		}
		var err error
		content, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(u.Host)))
		if err != nil {
			if cacheOK && useCacheOnErr {
				return cache.Load(cacheKey)
			}
			return nil, err
		}
	case "http", "https":
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			log.Printf("Failed to request %s: %v", safehttp.RedactURL(u), err)
			return nil, err
		}

		req.Header = http.Header{
			"User-Agent":                []string{UserAgent},
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
		resp, err := safehttp.Client.Do(req)
		if err != nil {
			if cacheOK && useCacheOnErr {
				return cache.Load(cacheKey)
			}
			log.Printf("Failed to request %s: %v", safehttp.RedactURL(u), err)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected HTTP status for %s: %s", safehttp.RedactURL(u), resp.Status)
			if cacheOK && useCacheOnErr {
				return cache.Load(cacheKey)
			}
			log.Printf("Failed to request %s: %v", safehttp.RedactURL(u), err)
			return nil, err
		}

		content, err = io.ReadAll(io.LimitReader(resp.Body, safehttp.MaxResponseBytes+1))
		if err != nil {
			if cacheOK && useCacheOnErr {
				return cache.Load(cacheKey)
			}
			return nil, err
		}
		if int64(len(content)) > safehttp.MaxResponseBytes {
			return nil, fmt.Errorf("response from %s exceeds %d bytes", safehttp.RedactURL(u), safehttp.MaxResponseBytes)
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	return content, nil
}
