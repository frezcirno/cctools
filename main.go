package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var token = os.Getenv("TOKEN")

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

		fsStore(fp, src)
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

func loadUpstreams() (tpl map[string]UpstreamSpec, err error) {
	upstreams_yaml := fsLoad("./upstreams.yaml")
	err = yaml.Unmarshal(upstreams_yaml, &tpl)
	return
}

func loadTemplate() (tpl map[string]interface{}, err error) {
	template_yaml := fsLoad("./template.yaml")

	err = yaml.Unmarshal(template_yaml, &tpl)
	if err != nil {
		log.Fatalf("Failed to load template: %v", err)
	}
	return
}

func getNumber(query url.Values, key string) (int, error) {
	if !query.Has(key) {
		return 0, nil
	}
	num, err := strconv.Atoi(query.Get(key))
	if err != nil {
		return 0, err
	}
	return num, nil
}

func getStringArray(query url.Values, key string) []string {
	str := query.Get(key)
	if str == "" {
		return []string{}
	}
	return strings.Split(str, ",")
}

type Attitude int

const (
	NO Attitude = iota
	YES
	NA
)

func getAttitude(query url.Values, key string) Attitude {
	if !query.Has(key) {
		return NA
	}
	str := strings.ToLower(query.Get(key))
	if _, ok := YES_ANSWER[str]; ok {
		return YES
	}
	if _, ok := NO_ANSWER[str]; ok {
		return NO
	}
	return NA
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		out      []byte
		ua       string
		instance map[string]interface{}
	)

	logRequest(r)
	query := r.URL.Query()

	cfg := Config{}
	cfg.Mode = Mode(query.Get("mode"))
	if cfg.Mode == "" {
		cfg.Mode = PROXY
	}
	cfg.Trusted = getAttitude(query, "trusted") == YES
	if cfg.Port, err = getNumber(query, "port"); err != nil {
		goto bad
	}
	if cfg.SocksPort, err = getNumber(query, "socks_port"); err != nil {
		goto bad
	}
	if cfg.RedirPort, err = getNumber(query, "redir_port"); err != nil {
		goto bad
	}
	if cfg.TproxyPort, err = getNumber(query, "tproxy_port"); err != nil {
		goto bad
	}
	if cfg.MixedPort, err = getNumber(query, "mixed_port"); err != nil {
		goto bad
	}
	if cfg.ControllerPort, err = getNumber(query, "controller_port"); err != nil {
		goto bad
	}
	cfg.Secret = query.Get("secret")
	cfg.Dns = getAttitude(query, "dns")
	cfg.DnsListen = query.Get("dns_listen")
	if cfg.DnsPort, err = getNumber(query, "dns_port"); err != nil {
		goto bad
	}
	cfg.Eth = query.Get("eth")
	cfg.KeepUpstreamSelector = getAttitude(query, "keep_upstream_selector") == YES
	cfg.Group = getStringArray(query, "group")
	if cfg.Upstreams, err = loadUpstreams(); err != nil {
		goto except
	}
	if cfg.Template, err = loadTemplate(); err != nil {
		goto except
	}
	cfg.Selector = getStringArray(query, "selector")
	cfg.Upstream = getStringArray(query, "upstream")
	cfg.ExpandRuleProviders = getAttitude(query, "no_rule_providers") == YES
	cfg.ProxyRuleProviders = getAttitude(query, "proxy_rule_providers") == YES

	ua = r.Header.Get("User-Agent")
	if strings.Contains(ua, "Windows") {
		cfg.Platform = Windows
	} else if strings.Contains(ua, "Linux") {
		cfg.Platform = Linux
	} else if strings.Contains(ua, "Android") {
		cfg.Platform = Android
	} else if strings.Contains(ua, "Darwin") {
		cfg.Platform = Darwin
	} else {
		cfg.Platform = Other
	}

	if err = cfg.Validate(); err != nil {
		goto bad
	}

	instance, err = cfg.generate(r)
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

bad:
	http.Error(w, err.Error(), http.StatusBadRequest)
	return

except:
	log.Printf("Internal Server Error: %v\n", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func handleFileOp(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != token {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	path := r.URL.Path[1:]
	if r.Method == "GET" {
		target_file := fsLoad(path)
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
	fileSize, err := formfile.Seek(0, io.SeekEnd) // Seek to the end of the file
	if err != nil {
		log.Printf("Failed to get file size: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, err = formfile.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek to the beginning of the file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data := make([]byte, fileSize)
	if _, err := formfile.Read(data); err != nil {
		log.Printf("Failed to save file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	fsStore(path, data)
}

func handleRuleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	rule_set_name := query.Get("rule-set")
	if rule_set_name == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	template, err := loadTemplate()
	if err != nil {
		log.Printf("Failed to load template: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rule_providers, ok := template["rule-providers"].(map[interface{}]interface{})
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rule_provider, ok := rule_providers[rule_set_name].(map[interface{}]interface{})
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	ruleUrl, ok := rule_provider["url"].(string)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	url, err := url.Parse(ruleUrl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	content, err := download(url, fmt.Sprintf("rule-%s.yaml", rule_set_name), 24*time.Hour, nil, 10, true)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(content)
}

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	http.HandleFunc("/clash/config.yaml", handleConfig)
	http.HandleFunc("/upstreams.yaml", handleFileOp)
	http.HandleFunc("/template.yaml", handleFileOp)
	http.HandleFunc("/rule-providers", handleRuleProviders)
	http.Handle("/convert", makeProxy())

	log.Printf("Starting server on port 9000...\n")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatal(err)
	}
}
