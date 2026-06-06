package main

import (
	"errors"
	"fmt"
)

// AirportSpec
type AirportSpec struct {
	Name          string   `yaml:"name"`
	Urls          []string `yaml:"urls"`
	Ttl           int      `yaml:"ttl"`
	Tags          []string `yaml:"tag"`
	UseCacheOnErr bool     `yaml:"use-cache-on-err"`
	Enable        *bool    `yaml:"enable"`
}

func (as *AirportSpec) enabled() bool {
	return as.Enable == nil || *as.Enable
}

func (as *AirportSpec) tags() []string {
	tags := append(as.Tags, as.Name, "all")
	return tags
}

// Airport is the set of proxies parsed from one upstream. Upstream
// proxy-groups are intentionally not retained: the output proxy-groups are
// synthesized fresh from the proxies in buildProxyGroups, so keeping the
// upstreams' own groups would be dead data.
type Airport struct {
	Proxies DictList `yaml:"proxies"`
}

func (airport *Airport) renameProxy(key string, new_key string) error {
	if airport.Proxies.get(new_key) != nil {
		return fmt.Errorf("proxy %s already exists", new_key)
	}

	proxy := airport.Proxies.get(key)
	if proxy == nil {
		return fmt.Errorf("proxy %s not found", key)
	}

	airport.Proxies.del(key)
	airport.Proxies.set(new_key, proxy)
	return nil
}

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

func (airport *Airport) removeProxy(key string) {
	airport.Proxies.del(key)
}

func (airport *Airport) filterProxy(filter func(YamlStrDict) bool) {
	toRemove := []string{}
	airport.Proxies.each(func(key string, proxy YamlStrDict) {
		if !filter(proxy) {
			toRemove = append(toRemove, key)
		}
	})
	for _, key := range toRemove {
		airport.removeProxy(key)
	}
}

// Platform
type Platform string

const (
	Windows Platform = "windows"
	Linux   Platform = "linux"
	Android Platform = "android"
	Darwin  Platform = "darwin"
	Other   Platform = "other"
)

// RuleProviderTransform
type RuleProviderTransform string

const (
	RPT_NONE   RuleProviderTransform = "none"
	RPT_PROXY  RuleProviderTransform = "proxy"
	RPT_INLINE RuleProviderTransform = "inline"
)

func StringToRuleProviderTransform(s string) (RuleProviderTransform, error) {
	switch s {
	case string(RPT_NONE), string(RPT_PROXY), string(RPT_INLINE):
		return RuleProviderTransform(s), nil
	default:
		return RPT_NONE, fmt.Errorf("invalid RuleProviderTransform: %s", s)
	}
}

// ExternalControllerType
type ExternalControllerType string

const (
	NONE  ExternalControllerType = ""
	HTTP  ExternalControllerType = "http"
	HTTPS ExternalControllerType = "https"
	UNIX  ExternalControllerType = "unix"
)

func StringToExternalControllerType(s string) (ExternalControllerType, error) {
	switch s {
	case string(NONE), string(HTTP), string(HTTPS), string(UNIX):
		return ExternalControllerType(s), nil
	default:
		return NONE, errors.New("invalid ExternalControllerType")
	}
}
