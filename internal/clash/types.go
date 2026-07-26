// Package clash renders a Clash/mihomo YAML config from a set of subscription
// upstreams and a base template.
//
// The base config (mode, dns/tun internals, hosts, cors, rule-providers and
// rules) is built in Go by DefaultTemplate; a Config describes the per-request
// overrides and Generate produces the final document.
package clash

import (
	"errors"
	"fmt"
	"net/url"
)

// YamlStrDict is the in-memory shape of every YAML mapping we manipulate.
type YamlStrDict map[string]any

func asString(v any, field string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s is not a string", field)
	}
	return s, nil
}

func asStringList(v any, field string) ([]string, error) {
	switch vv := v.(type) {
	case []string:
		return append([]string(nil), vv...), nil
	case []any:
		res := make([]string, 0, len(vv))
		for idx, item := range vv {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d] is not a string", field, idx)
			}
			res = append(res, s)
		}
		return res, nil
	default:
		return nil, fmt.Errorf("%s is not a string list", field)
	}
}

func asAnyList(v any, field string) ([]any, error) {
	switch vv := v.(type) {
	case []any:
		return vv, nil
	case []string:
		res := make([]any, 0, len(vv))
		for _, item := range vv {
			res = append(res, item)
		}
		return res, nil
	default:
		return nil, fmt.Errorf("%s is not a list", field)
	}
}

func asStringAnyMap(v any, field string) (map[string]any, error) {
	switch vv := v.(type) {
	case map[string]any:
		return vv, nil
	case YamlStrDict:
		return map[string]any(vv), nil
	default:
		return nil, fmt.Errorf("%s is not a map", field)
	}
}

func asStringAnyMapField(m map[string]any, key string) (map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%s not found", key)
	}
	return asStringAnyMap(v, key)
}

// BaseURL is how a generated config should address this server, used to rewrite
// rule-provider URLs back through /rule-providers and /convert.
type BaseURL struct {
	Scheme string
	Host   string
}

// String renders the origin, e.g. "https://sub.example.com".
func (b BaseURL) String() string {
	return fmt.Sprintf("%s://%s", b.Scheme, b.Host)
}

// Resolve turns a possibly-relative URL into an absolute one rooted at b.
func (b BaseURL) Resolve(raw string) string {
	if raw == "" {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.IsAbs() {
		return raw
	}
	return b.String() + raw
}

// InvalidConfigError signals that the requested options are out of range or
// mutually inconsistent, so the request should fail (400) rather than emit a
// broken config. Generate returns it before fetching anything.
type InvalidConfigError struct{ Err error }

func (e *InvalidConfigError) Error() string { return e.Err.Error() }
func (e *InvalidConfigError) Unwrap() error { return e.Err }

// UpstreamUnavailableError signals that no usable proxy data could be collected
// from any configured upstream, so the request should fail (502) rather than
// return a syntactically valid but proxy-less config.
type UpstreamUnavailableError struct{ Err error }

func (e *UpstreamUnavailableError) Error() string { return e.Err.Error() }
func (e *UpstreamUnavailableError) Unwrap() error { return e.Err }

// Platform is the client OS, detected from the request User-Agent.
type Platform string

const (
	Windows Platform = "windows"
	Linux   Platform = "linux"
	Android Platform = "android"
	Darwin  Platform = "darwin"
	Other   Platform = "other"
)

// RuleProviderTransform selects how template rule-providers are rewritten:
// passed through, proxied via this server, or inlined as literal rules.
type RuleProviderTransform string

const (
	RPT_NONE   RuleProviderTransform = "none"
	RPT_PROXY  RuleProviderTransform = "proxy"
	RPT_INLINE RuleProviderTransform = "inline"
)

func ParseRuleProviderTransform(s string) (RuleProviderTransform, error) {
	switch s {
	case string(RPT_NONE), string(RPT_PROXY), string(RPT_INLINE):
		return RuleProviderTransform(s), nil
	default:
		return RPT_NONE, fmt.Errorf("invalid RuleProviderTransform: %s", s)
	}
}

// ExternalControllerType selects which external-controller listener the
// generated config exposes (if any).
type ExternalControllerType string

const (
	NONE  ExternalControllerType = ""
	HTTP  ExternalControllerType = "http"
	HTTPS ExternalControllerType = "https"
	UNIX  ExternalControllerType = "unix"
)

func ParseExternalControllerType(s string) (ExternalControllerType, error) {
	switch s {
	case string(NONE), string(HTTP), string(HTTPS), string(UNIX):
		return ExternalControllerType(s), nil
	default:
		return NONE, errors.New("invalid ExternalControllerType")
	}
}
