package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/frezcirno/cctools/internal/clash"
)

// badRequestError marks a failure caused by the caller's parameters (→ 400),
// as opposed to an internal failure (→ 500) or a dead upstream (→ 502).
type badRequestError struct{ error }

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	query := r.URL.Query()

	if len(query) == 0 {
		serveIndex(w, r)
		return
	}

	out, err := buildConfig(r)
	if err != nil {
		var badRequest *badRequestError
		var invalidConfig *clash.InvalidConfigError
		var unavailable *clash.UpstreamUnavailableError
		if errors.As(err, &badRequest) || errors.As(err, &invalidConfig) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else if errors.As(err, &unavailable) {
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

func buildConfig(r *http.Request) ([]byte, error) {
	query := r.URL.Query()
	warnUnknownQueryParams(query)

	c := clash.Config{}
	var err error

	// Parse and reject bad parameters before touching the filesystem or the
	// network, so a malformed request costs nothing and always surfaces as 400.
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
	if c.ExternalControllerType, err = clash.ParseExternalControllerType(getString(query, "external_controller_type")); err != nil {
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

	if c.RuleProviderTransform, err = clash.ParseRuleProviderTransform(getString(query, "rule_provider_transform")); err != nil {
		return nil, &badRequestError{err}
	}

	c.Platform = detectPlatform(r.Header.Get("User-Agent"))

	if c.Upstreams, err = loadUpstreams(); err != nil {
		return nil, err
	}
	if c.Template, err = loadTemplate(); err != nil {
		return nil, err
	}

	// Generate validates the assembled options itself and reports an
	// inconsistent Config as *clash.InvalidConfigError, which handleConfig maps
	// to 400 alongside the parameter-parsing failures above.
	instance, err := c.Generate(baseURL(r))
	if err != nil {
		return nil, err
	}

	return yaml.Marshal(instance)
}

func detectPlatform(ua string) clash.Platform {
	switch {
	case strings.Contains(ua, "Windows"):
		return clash.Windows
	case strings.Contains(ua, "Linux"):
		return clash.Linux
	case strings.Contains(ua, "Android"):
		return clash.Android
	case strings.Contains(ua, "Darwin"):
		return clash.Darwin
	default:
		return clash.Other
	}
}

// knownConfigQueryKeys is the allowlist behind warnUnknownQueryParams. Every
// new query parameter must be registered here.
var knownConfigQueryKeys = map[string]struct{}{
	"upstream":   {},
	"organizer":  {},
	"top_select": {},
	// Accepted but currently ignored by the backend (the front-end still sends
	// these). Wiring them up — or removing the corresponding form controls — is
	// tracked separately; they are whitelisted here only to avoid per-request
	// "unrecognized query parameter" log spam.
	"keep_upstream_select":       {},
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

// --- query parameter coercion ---

var yesAnswer = map[string]struct{}{
	"":     {},
	"1":    {},
	"on":   {},
	"y":    {},
	"yes":  {},
	"t":    {},
	"true": {},
}

var noAnswer = map[string]struct{}{
	"0":     {},
	"off":   {},
	"n":     {},
	"no":    {},
	"f":     {},
	"false": {},
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

var sep = regexp.MustCompile("[,;]+")

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
	for _, userKV := range sep.Split(str, -1) {
		// Split on the last colon, e.g. "geosite:cn:223.5.5.5" → key="geosite:cn", value="223.5.5.5"
		idx := strings.LastIndex(userKV, ":")
		if idx < 0 {
			return nil, &ErrInvalid{userKV}
		}
		k := strings.TrimSpace(userKV[:idx])
		v := strings.TrimSpace(userKV[idx+1:])
		m[k] = v
	}
	return m, nil
}

func getBool(query url.Values, key string) (bool, error) {
	if query.Has(key) {
		str := strings.ToLower(query.Get(key))
		if _, ok := yesAnswer[str]; ok {
			return true, nil
		}
		if _, ok := noAnswer[str]; ok {
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
