package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var token = os.Getenv("TOKEN")

var fake_fs = map[string][]byte{}

func fake_store(fspath string, data []byte) {
	key := resolvePath(fspath)
	fake_fs[key] = data
}

func fake_load(fspath string) []byte {
	key := resolvePath(fspath)
	return fake_fs[key]
}

func resolvePath(fspath string) string {
	// Convert the relative path to an absolute path
	absPath, err := filepath.Abs(fspath)
	if err != nil {
		// Handle error, for example, log it or return a default value
		fmt.Println("Error resolving path:", err)
		return fspath
	}
	return absPath
}

func init() {
	for _, fp := range []string{"./upstreams.yaml", "./template.yaml"} {
		f, err := os.Open(fp)
		if err != nil {
			log.Panicf("Failed to open upstreams.yaml: %v\n", err)
			return
		}
		defer f.Close()

		src, err := io.ReadAll(f)
		if err != nil {
			log.Panicf("Failed to read upstreams.yaml: %v\n", err)
			return
		}

		fake_store(fp, src)
	}
}

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
	tpl := map[string]UpstreamSpec{}

	upstreams_yaml := fake_load("./upstreams.yaml")
	err := yaml.Unmarshal(upstreams_yaml, &tpl)
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
		if !query.Has(key) {
			return false, nil
		}
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
		return NA, fmt.Errorf("invalid option: %s", str)
	}

	cfg := Config{}
	cfg.Mode = Mode(query.Get("mode"))
	if cfg.Mode == "" {
		cfg.Mode = PROXY
	}
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
	cfg.NoRuleProviders, _ = GetBool("no_rule_providers")
	cfg.Platform = query.Get("platform")

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

func handle_file_op(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != token {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	path := r.URL.Path[1:]
	if r.Method == "GET" {
		target_file := fake_load(path)
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Write(target_file)
		return
	}

	// 上传文件
	formfile, _, err := r.FormFile("file")
	if err != nil {
		log.Printf("Failed to upload file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 保存到本地
	data := []byte{}
	if _, err := formfile.Read(data); err != nil {
		log.Printf("Failed to save file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	fake_store(path, data)
}

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	http.HandleFunc("/clash/config.yaml", handle_config)
	http.HandleFunc("/upstreams.yaml", handle_file_op)
	http.HandleFunc("/template.yaml", handle_file_op)

	log.Printf("Starting server on port 9000...\n")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatal(err)
	}
}
