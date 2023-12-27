package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func logRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Failed to dump request: %v\n", err)
	} else {
		log.Printf("%s Request: %s\n", time.Now().Format("2006-01-02 15:04:05"), string(requestDump))
	}
}

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

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "baidu.com",
	})

	proxy.Director = func(req *http.Request) {
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

	proxy.ModifyResponse = func(resp *http.Response) error {
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

	http.Handle("/", proxy)

	log.Printf("Starting server on port 9000...\n")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatal(err)
	}
}
