package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func download(url *url.URL,
	cache_key string,
	ttl time.Duration,
	postprocesser func([]byte) []byte,
	timeout int,
	use_cache_on_err bool,
) ([]byte, error) {
	if cache_key == "" {
		cache_key = fmt.Sprintf("%x", sha1.Sum([]byte(url.String())))
	}
	save_path := "./cache/" + cache_key
	log.Printf("Retrieving %s, cache: %s, ttl: %d, use-cache-on-err: %v", url, save_path, ttl, use_cache_on_err)
	cache_ok := false

	if fi, err := fsStat(save_path); err == nil {
		now := time.Now()
		ctime := fi.ModTime()
		if ctime.After(now) {
			log.Printf("Clock reverted")
		} else if now.Sub(ctime) < ttl {
			log.Printf("Cache hit")
			return fsLoad(save_path)
		} else { // expired or ttl == 0
			cache_ok = true
		}
	}

	var content []byte

	if url.Scheme == "file" {
		var err error
		if content, err = fsLoad(url.Path); err != nil {
			return nil, err
		}
	} else if url.Scheme == "base64" {
		var err error
		content, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(url.Host)))
		if err != nil {
			return nil, err
		}
	} else { // http, https
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
		if err != nil {
			log.Printf("Failed to request %s: %v", url, err)
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
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if err != nil {
				resp.Body.Close()
			}
			if cache_ok && use_cache_on_err {
				return fsLoad(save_path)
			}
			if err == nil {
				err = fmt.Errorf("status code %d", resp.StatusCode)
			}
			return nil, err
		}
		defer resp.Body.Close()

		content, err = io.ReadAll(resp.Body)
		if err != nil {
			if cache_ok && use_cache_on_err {
				return fsLoad(save_path)
			}
			return nil, err
		}
	}

	if postprocesser != nil {
		content = postprocesser(content)
	}

	if _, err := os.LookupEnv("DISABLE_CACHE"); !err {
		os.MkdirAll("./cache", os.ModePerm)
		if f, err := os.Create(save_path); err == nil {
			defer f.Close()
			f.Write(content)
		}
	}

	return content, nil
}
