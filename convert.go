package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func convertRawListToRuleProvider(rawList []byte) []byte {
	rules := make([][]byte, 0)
	lines := bytes.Split(rawList, []byte("\n"))

	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || bytes.HasPrefix(l, []byte("#")) {
			rules = append(rules, l)
		} else {
			rules = append(rules, []byte(" - "+string(l)))
		}
	}

	for i := range rules {
		if bytes.HasPrefix(rules[i], []byte(" - ")) {
			rules = append(rules[:i], append([][]byte{[]byte("payload:")}, rules[i:]...)...)
			break
		}
	}

	return bytes.Join(rules, []byte("\n"))
}

func makeProxy() *httputil.ReverseProxy {
	revProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "baidu.com",
	})

	revProxy.Director = func(req *http.Request) {
		logRequest(req)

		upstream := req.URL.Query().Get("url")
		if upstream == "" {
			return
		}

		upstreamURL, err := url.Parse(upstream)
		if err != nil {
			return
		}

		req.URL = upstreamURL
		req.Host = upstreamURL.Host

		req.Header["Host"] = []string{upstreamURL.Host}
		req.Header["X-Forwarded-For"] = nil
		req.Header["Accept-Encoding"] = nil
	}

	revProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)

		b := buf.Bytes()
		newb := convertRawListToRuleProvider(b)
		newbuf := bytes.NewBuffer(newb)

		resp.Body = io.NopCloser(newbuf)
		resp.ContentLength = int64(newbuf.Len())
		resp.Header["Content-Length"] = []string{fmt.Sprint(newbuf.Len())}

		return nil
	}

	return revProxy
}
