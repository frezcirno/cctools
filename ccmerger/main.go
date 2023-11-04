package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

func logRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Failed to dump request: %v\n", err)
	} else {
		log.Printf("%s Request: %s\n", time.Now().Format("2006-01-02 15:04:05"), string(requestDump))
	}
}

var YES_ANSWER = map[string]struct{}{
	"":     {},
	"1":    {},
	"on":   {},
	"y":    {},
	"yes":  {},
	"t":    {},
	"true": {},
}

var NO_ANSWER = map[string]struct{}{
	"0":     {},
	"off":   {},
	"n":     {},
	"no":    {},
	"f":     {},
	"false": {},
}

func loadAllUpstreams() (map[string]UpstreamSpec, error) {
	f, err := os.Open("./upstreams.yaml")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	tpl := map[string]UpstreamSpec{}
	err = yaml.Unmarshal(src, &tpl)
	if err != nil {
		return nil, err
	}

	return tpl, nil
}

func handle_config(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		out      []byte
		instance map[string]interface{}
	)

	logRequest(r)

	query := r.URL.Query()

	GetNumber := func(key string) (int, error) {
		if !query.Has(key) {
			return 0, nil
		}
		num, err := strconv.Atoi(query.Get(key))
		if err != nil {
			return 0, err
		}
		return num, nil
	}

	GetArray := func(key string) ([]string, error) {
		str := query.Get(key)
		if str == "" {
			return []string{}, nil
		}
		return strings.Split(str, ","), nil
	}

	GetBool := func(key string) (bool, error) {
		str := strings.ToLower(query.Get(key))
		_, ok := YES_ANSWER[str]
		return ok, nil
	}

	GetAttitude := func(key string) (Attitude, error) {
		if !query.Has(key) {
			return NA, nil
		}

		str := strings.ToLower(query.Get(key))
		if _, ok := YES_ANSWER[str]; ok {
			return YES, nil
		}
		if _, ok := NO_ANSWER[str]; ok {
			return NO, nil
		}
		return NA, fmt.Errorf("Invalid option: %s", str)
	}

	cfg := Config{}
	cfg.Mode = Mode(query.Get("mode"))
	cfg.Trusted, _ = GetBool("trusted")
	if cfg.Port, err = GetNumber("port"); err != nil {
		goto die
	}
	if cfg.SocksPort, err = GetNumber("socks_port"); err != nil {
		goto die
	}
	if cfg.RedirPort, err = GetNumber("redir_port"); err != nil {
		goto die
	}
	if cfg.TproxyPort, err = GetNumber("tproxy_port"); err != nil {
		goto die
	}
	if cfg.MixedPort, err = GetNumber("mixed_port"); err != nil {
		goto die
	}
	if cfg.ControllerPort, err = GetNumber("controller_port"); err != nil {
		goto die
	}
	cfg.Secret = query.Get("secret")
	if cfg.Dns, err = GetAttitude("dns"); err != nil {
		goto die
	}
	cfg.DnsListen = query.Get("dns_listen")
	if cfg.DnsPort, err = GetNumber("dns_port"); err != nil {
		goto die
	}
	cfg.Eth = query.Get("eth")
	cfg.KeepUpstreamSelector, _ = GetBool("keep_upstream_selector")
	cfg.Group, _ = GetArray("group")
	if cfg.AllUpstream, err = loadAllUpstreams(); err != nil {
		goto except
	}
	cfg.Selector, _ = GetArray("selector")
	cfg.Upstream, _ = GetArray("upstream")

	if err = cfg.Validate(); err != nil {
		goto die
	}

	instance, err = cfg.generate()
	if err != nil {
		goto except
	}

	out, err = yaml.Marshal(instance)
	if err != nil {
		goto except
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(out)
	return

die:
	http.Error(w, err.Error(), http.StatusBadRequest)
	return

except:
	log.Printf("Internal Server Error: %v\n", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	http.HandleFunc("/clash/config.yaml", handle_config)

	log.Printf("Starting server on port 9000...\n")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatal(err)
	}
}
