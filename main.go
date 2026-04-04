package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var token = os.Getenv("TOKEN")

func init() {
	for _, fp := range []string{"./upstreams.yaml", "./template.yaml"} {
		f, err := os.Open(fp)
		if err != nil {
			log.Panicf("Failed to open %s: %v\n", fp, err)
		}

		src, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			log.Panicf("Failed to read %s: %v\n", fp, err)
		}

		fsStore(fp, src)
	}
}

func logRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Failed to dump request: %v\n", err)
		return
	}
	// Sanitize sensitive data before logging
	dumpStr := string(requestDump)
	sensitiveFields := []string{"token", "secret", "external_controller_addr", "nameserver_policy"}
	for _, field := range sensitiveFields {
		// Sanitize query parameters
		re := regexp.MustCompile(`(?i)` + field + `=([^&\s]+)`)
		dumpStr = re.ReplaceAllString(dumpStr, field+"=[REDACTED]")
		// Sanitize header values
		re = regexp.MustCompile(`(?i)(` + field + `:\s*)([^\r\n]+)`)
		dumpStr = re.ReplaceAllString(dumpStr, "${1}[REDACTED]")
	}
	log.Printf("%s Request: %s\n", time.Now().Format("2006-01-02 15:04:05"), dumpStr)
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

func loadUpstreams() (tpl map[string]AirportSpec, err error) {
	upstreams_yaml, err := fsLoad("./upstreams.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load upstreams.yaml: %w", err)
	}
	err = yaml.Unmarshal(upstreams_yaml, &tpl)
	return
}

func loadTemplate() (tpl map[string]any, err error) {
	template_yaml, err := fsLoad("./template.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load template.yaml: %w", err)
	}
	err = yaml.Unmarshal(template_yaml, &tpl)
	return
}

func getString(query url.Values, key string) string {
	return query.Get(key)
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

var sep *regexp.Regexp = regexp.MustCompile("[,;]+")

func getStringArray(query url.Values, key string) []string {
	str := query.Get(key)
	if str == "" {
		return []string{}
	}
	res := sep.Split(str, -1)
	for i, s := range res {
		res[i] = strings.TrimSpace(s)
	}
	return res
}

func getStringMap(query url.Values, key string) (map[string]string, error) {
	str := query.Get(key)
	if str == "" {
		return map[string]string{}, nil
	}
	m := map[string]string{}
	for _, user_kv := range sep.Split(str, -1) {
		// Split on the last colon, e.g. "geosite:cn:223.5.5.5" → key="geosite:cn", value="223.5.5.5"
		idx := strings.LastIndex(user_kv, ":")
		if idx < 0 {
			return nil, &ErrInvalid{user_kv}
		}
		k := strings.TrimSpace(user_kv[:idx])
		v := strings.TrimSpace(user_kv[idx+1:])
		m[k] = v
	}
	return m, nil
}

type ErrInvalid struct {
	string
}

func (e *ErrInvalid) Error() string {
	return fmt.Sprintf("invalid argument: %s", e.string)
}

type ErrNotExist struct {
	string
}

func (e *ErrNotExist) Error() string {
	return fmt.Sprintf("missing required argument: %s", e.string)
}

func getBool(query url.Values, key string) (bool, error) {
	if query.Has(key) {
		user_str := query.Get(key)
		str := strings.ToLower(user_str)
		if _, ok := YES_ANSWER[str]; ok {
			return true, nil
		}
		if _, ok := NO_ANSWER[str]; ok {
			return false, nil
		}
		return false, &ErrInvalid{key}
	}
	return false, &ErrNotExist{key}
}

func getBoolOrDefault(query url.Values, key string, def bool) (bool, error) {
	b, err := getBool(query, key)
	if err == nil {
		return b, nil
	}
	if _, ok := err.(*ErrNotExist); ok {
		return def, nil
	}
	return false, err

}

var knownConfigQueryKeys = map[string]struct{}{
	"upstream":                   {},
	"organizer":                  {},
	"top_select":                 {},
	"keep_upstream_selector":     {},
	"port_proxy":                 {},
	"bind_address":               {},
	"port":                       {},
	"socks_port":                 {},
	"mixed_port":                 {},
	"tproxy":                     {},
	"redir_port":                 {},
	"tproxy_port":                {},
	"allow_lan":                  {},
	"external_controller_type":   {},
	"external_controller_addr":   {},
	"external_controller_secret": {},
	"dns":                        {},
	"dns_listen":                 {},
	"enhanced_mode":              {},
	"default_nameserver":         {},
	"nameserver":                 {},
	"fallback":                   {},
	"nameserver_policy":          {},
	"tun":                        {},
	"tun_stack":                  {},
	"rule_provider_transform":    {},
	"custom_rules":               {},
	"log_level":                  {},
}

func warnUnknownQueryParams(query url.Values) {
	for key := range query {
		if _, ok := knownConfigQueryKeys[key]; !ok {
			log.Printf("Warning: unrecognized query parameter %q", key)
		}
	}
}

type badRequestError struct{ error }

func buildConfig(r *http.Request) ([]byte, error) {
	query := r.URL.Query()
	warnUnknownQueryParams(query)

	c := Config{}
	var err error

	if c.Upstreams, err = loadUpstreams(); err != nil {
		return nil, err
	}
	if c.Template, err = loadTemplate(); err != nil {
		return nil, err
	}

	c.Upstream = getStringArray(query, "upstream")
	c.Organizer = getStringArray(query, "organizer")
	c.TopSelect = getStringArray(query, "top_select")
	if c.KeepUpstreamSelector, err = getBoolOrDefault(query, "keep_upstream_selector", false); err != nil {
		return nil, &badRequestError{err}
	}

	if c.PortProxy, err = getBoolOrDefault(query, "port_proxy", false); err != nil {
		return nil, &badRequestError{err}
	}
	c.BindAddress = getString(query, "bind_address")
	if c.HttpPort, err = getNumber(query, "port"); err != nil {
		return nil, &badRequestError{err}
	}
	if c.SocksPort, err = getNumber(query, "socks_port"); err != nil {
		return nil, &badRequestError{err}
	}
	if c.MixedPort, err = getNumber(query, "mixed_port"); err != nil {
		return nil, &badRequestError{err}
	}

	if c.TransProxy, err = getBoolOrDefault(query, "tproxy", false); err != nil {
		return nil, &badRequestError{err}
	}
	if c.RedirPort, err = getNumber(query, "redir_port"); err != nil {
		return nil, &badRequestError{err}
	}
	if c.TproxyPort, err = getNumber(query, "tproxy_port"); err != nil {
		return nil, &badRequestError{err}
	}

	if c.AllowLan, err = getBoolOrDefault(query, "allow_lan", false); err != nil {
		return nil, &badRequestError{err}
	}
	if c.ExternalControllerType, err = StringToExternalControllerType(getString(query, "external_controller_type")); err != nil {
		return nil, &badRequestError{err}
	}
	c.ExternalControllerAddr = getString(query, "external_controller_addr")
	c.ExternalControllerSecret = getString(query, "external_controller_secret")

	if c.Dns, err = getBoolOrDefault(query, "dns", false); err != nil {
		return nil, &badRequestError{err}
	}
	c.DnsListen = getString(query, "dns_listen")
	c.EnhancedMode = getString(query, "enhanced_mode")
	c.DefaultNameserver = getStringArray(query, "default_nameserver")
	c.Nameserver = getStringArray(query, "nameserver")
	c.Fallback = getStringArray(query, "fallback")
	if c.NameserverPolicy, err = getStringMap(query, "nameserver_policy"); err != nil {
		return nil, &badRequestError{err}
	}

	if c.Tun, err = getBoolOrDefault(query, "tun", false); err != nil {
		return nil, &badRequestError{err}
	}
	c.TunStack = getString(query, "tun_stack")
	c.LogLevel = getString(query, "log_level")

	if c.RuleProviderTransform, err = StringToRuleProviderTransform(getString(query, "rule_provider_transform")); err != nil {
		return nil, &badRequestError{err}
	}

	ua := r.Header.Get("User-Agent")
	if strings.Contains(ua, "Windows") {
		c.Platform = Windows
	} else if strings.Contains(ua, "Linux") {
		c.Platform = Linux
	} else if strings.Contains(ua, "Android") {
		c.Platform = Android
	} else if strings.Contains(ua, "Darwin") {
		c.Platform = Darwin
	} else {
		c.Platform = Other
	}

	if err = c.Validate(); err != nil {
		return nil, &badRequestError{err}
	}

	instance, err := c.generate(r)
	if err != nil {
		return nil, err
	}

	return yaml.Marshal(instance)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	query := r.URL.Query()

	if len(query) == 0 {
		http.ServeFile(w, r, "index.html")
		return
	}

	out, err := buildConfig(r)
	if err != nil {
		if _, ok := err.(*badRequestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			log.Printf("Internal Server Error: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(out)
}

func handleFileOp(w http.ResponseWriter, r *http.Request) {
	// Support multiple authentication methods: query token, Authorization header, X-Auth-Token header
	authToken := r.URL.Query().Get("token")
	if authToken == "" {
		authToken = r.Header.Get("Authorization")
		if authToken != "" && strings.HasPrefix(authToken, "Bearer ") {
			authToken = strings.TrimPrefix(authToken, "Bearer ")
		}
	}
	if authToken == "" {
		authToken = r.Header.Get("X-Auth-Token")
	}
	if authToken != token {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	path := r.URL.Path[1:]
	if r.Method == http.MethodGet {
		target_file, _ := fsLoad(path)
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
	defer formfile.Close()

	// Use io.ReadAll for robust multipart file reading
	data, err := io.ReadAll(formfile)
	if err != nil {
		log.Printf("Failed to read file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	fsStore(path, data)
}

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	http.HandleFunc("/clash/config.yaml", handleConfig)
	http.HandleFunc("/upstreams.yaml", handleFileOp)
	http.HandleFunc("/template.yaml", handleFileOp)
	http.HandleFunc("/rule-providers", handleRuleProviders)
	http.Handle("/convert", makeProxy())

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9000"
	}
	log.Printf("Starting server on %s...\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}
