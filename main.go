package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

var token = os.Getenv("TOKEN")

func init() {
	// Only upstreams.yaml is preloaded from disk. template.yaml is no longer
	// required: the base config is built in Go (defaultTemplate, template.go);
	// an on-disk template.yaml is an optional override loaded lazily.
	for _, fp := range []string{"./upstreams.yaml"} {
		src, err := os.ReadFile(fp)
		if err != nil {
			// Don't crash on boot: the file may be supplied later via the
			// token-gated upload endpoint, and on a read-only/serverless FS it
			// may live elsewhere. Requests surface a clear error until it exists.
			log.Printf("Warning: %s not loaded at startup: %v", fp, err)
			continue
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
	// Sanitize sensitive data before logging. Covered as both query params
	// (field=value) and header values (Field: value): "url" hides the /convert
	// subscription URL (which embeds tokens), "authorization"/"x-auth-token"
	// hide the file-op credentials.
	dumpStr := string(requestDump)
	sensitiveFields := []string{"token", "secret", "external_controller_addr", "nameserver_policy", "url", "authorization", "x-auth-token"}
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

func loadTemplate() (map[string]any, error) {
	// The built-in defaultTemplate() (template.go) is the source of truth for
	// the base config. A template.yaml on disk — e.g. uploaded via the
	// token-gated endpoint — overrides it when present, for ad-hoc tweaks.
	if _, err := fsStat("./template.yaml"); err == nil {
		template_yaml, err := fsLoad("./template.yaml")
		if err != nil {
			return nil, fmt.Errorf("failed to load template.yaml: %w", err)
		}
		var tpl map[string]any
		if err := yaml.Unmarshal(template_yaml, &tpl); err != nil {
			return nil, fmt.Errorf("failed to parse template.yaml: %w", err)
		}
		return tpl, nil
	}
	return defaultTemplate(), nil
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
	"upstream":   {},
	"organizer":  {},
	"top_select": {},
	// Accepted but currently ignored by the backend (the front-end still sends
	// these). Wiring them up — or removing the corresponding form controls — is
	// tracked separately; they are whitelisted here only to avoid per-request
	// "unrecognized query parameter" log spam.
	"keep_upstream_selector":     {},
	"custom_rules":               {},
	"tun_auto_route":             {},
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

// upstreamUnavailableError signals that no usable proxy data could be collected
// from any configured upstream, so the request should fail (502) rather than
// return a syntactically valid but proxy-less config.
type upstreamUnavailableError struct{ error }

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
		// The form is edited in-repo and served straight from disk; tell the
		// browser to always revalidate so UI changes are never masked by a
		// stale cached copy.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, "index.html")
		return
	}

	out, err := buildConfig(r)
	if err != nil {
		if _, ok := err.(*badRequestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else if _, ok := err.(*upstreamUnavailableError); ok {
			log.Printf("Upstream unavailable: %v\n", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		} else {
			log.Printf("Internal Server Error: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(out)
}

// handleUpstreamList returns the selectable upstreams (enabled only) as JSON so
// the front-end form can render one checkbox per upstream. Only names and the
// "default" flag are exposed — never the upstream URLs (which embed tokens).
func handleUpstreamList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	upstreams, err := loadUpstreams()
	if err != nil {
		log.Printf("Failed to load upstreams for list: %v\n", err)
		http.Error(w, "failed to load upstreams", http.StatusInternalServerError)
		return
	}

	type upstreamOption struct {
		Label   string `json:"label"`   // human-readable name shown in the form
		Value   string `json:"value"`   // tag sent as ?upstream=<value>
		Default bool   `json:"default"` // part of the implicit "default" selection
	}

	keys := make([]string, 0, len(upstreams))
	for k := range upstreams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	options := make([]upstreamOption, 0, len(keys))
	for _, key := range keys {
		spec := upstreams[key]
		if !spec.enabled() {
			continue
		}
		// The value must be a tag that selectedUpstreams matches on: prefer the
		// name, then an explicit tag, then the map key.
		value := spec.Name
		if value == "" {
			if len(spec.Tags) > 0 {
				value = spec.Tags[0]
			} else {
				value = key
			}
		}
		label := spec.Name
		if label == "" {
			label = key
		}
		isDefault := false
		for _, t := range spec.tags() {
			if t == "default" {
				isDefault = true
				break
			}
		}
		options = append(options, upstreamOption{Label: label, Value: value, Default: isDefault})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		log.Printf("Failed to encode upstream list: %v\n", err)
	}
}

func handleFileOp(w http.ResponseWriter, r *http.Request) {
	// Fail closed: if no TOKEN is configured, the read/write endpoints are
	// disabled entirely rather than open to everyone (an empty token must never
	// authenticate an empty credential).
	if token == "" {
		http.Error(w, "file operations are disabled: TOKEN is not configured", http.StatusForbidden)
		return
	}

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
	if subtle.ConstantTimeCompare([]byte(authToken), []byte(token)) != 1 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	path := r.URL.Path[1:]
	if r.Method == http.MethodGet {
		target_file, err := fsLoad(path)
		if err != nil {
			// No on-disk override: for template.yaml, fall back to the built-in
			// default (template.go) so callers can still inspect/download the
			// effective base config instead of getting a 404.
			if path == "template.yaml" {
				if out, mErr := yaml.Marshal(defaultTemplate()); mErr == nil {
					w.Header().Set("Content-Type", "application/x-yaml")
					w.Write(out)
					return
				}
			}
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
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

// recoverMiddleware turns any panic that escapes a handler into a 500 instead
// of a dropped connection, so a single bad request can never take the server
// down. (Panics in handler-spawned goroutines must still be recovered at their
// own goroutine boundary — see fetchAirports.)
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Recovered from panic handling %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	// 设置日志前缀和输出位置
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	mux := http.NewServeMux()
	mux.HandleFunc("/clash/config.yaml", handleConfig)
	mux.HandleFunc("/upstreams.yaml", handleFileOp)
	mux.HandleFunc("/template.yaml", handleFileOp)
	mux.HandleFunc("/upstreams-list", handleUpstreamList)
	mux.HandleFunc("/rule-providers", handleRuleProviders)
	mux.Handle("/convert", makeProxy())

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9000"
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           recoverMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second, // primary Slowloris defense
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second, // generous: config generation fetches upstreams
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("Starting server on %s...\n", listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-idleClosed
}
