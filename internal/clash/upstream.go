package clash

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/frezcirno/cctools/internal/cache"
	"github.com/frezcirno/cctools/internal/fetch"
	"github.com/frezcirno/cctools/internal/safehttp"
)

func downloadUpstream(upstream *url.URL, upstreamName string, ttlSec int, timeout int, useCacheOnErr bool) (*Airport, error) {
	ttl := time.Duration(ttlSec) * time.Second
	cacheKey := cache.Key(upstream)
	// Upstreams may legitimately use file:// / base64:// (operator-configured,
	// token-gated), so local schemes are allowed here.
	content, err := fetch.Download(upstream, upstreamName, ttl, timeout, useCacheOnErr, true)
	if err != nil {
		log.Printf("Failed to download upstream %v: %v", safehttp.RedactURL(upstream), err)
		return nil, err
	}

	airport, err := parseUpstream(content)
	if err != nil {
		log.Printf("Failed to parse downloaded upstream %v: %v", safehttp.RedactURL(upstream), err)

		cacheOK, _ := cache.IsOK(cacheKey, ttl)
		if useCacheOnErr && cacheOK {
			log.Printf("Retry cached upstream for %v", safehttp.RedactURL(upstream))
			content, err := cache.Load(cacheKey)
			if err == nil {
				return parseUpstream(content)
			}
		}

		return nil, err
	}

	cache.Save(cacheKey, content)
	return airport, nil
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
