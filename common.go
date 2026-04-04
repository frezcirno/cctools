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

// Airport
type Airport struct {
	Proxies DictList `yaml:"proxies"`
	Groups  DictList `yaml:"groups"`
}

func NewAirport() Airport {
	return Airport{
		Proxies: NewEmptyDictList(),
		Groups:  NewEmptyDictList(),
	}
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

	airport.Groups.each(func(_ string, group YamlStrDict) {
		groupProxies, ok := group["proxies"]
		if !ok {
			return
		}
		groupProxiesL, err := normalizeProxyNames(groupProxies)
		if err != nil {
			return
		}
		for idx, groupProxy := range groupProxiesL {
			if groupProxy == key {
				groupProxiesL[idx] = new_key
			}
		}
		group["proxies"] = groupProxiesL
	})
	return nil
}

func (airport *Airport) renameGroup(key string, new_key string) error {
	group := airport.Groups.get(key)
	if group == nil {
		return fmt.Errorf("group %s not found", key)
	}

	airport.Groups.del(key)
	airport.Groups.set(new_key, group)

	return nil
}

func normalizeProxyNames(v any) ([]string, error) {
	switch vv := v.(type) {
	case []string:
		return append([]string(nil), vv...), nil
	case []any:
		res := make([]string, 0, len(vv))
		for _, item := range vv {
			name, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid proxy entry type %T", item)
			}
			res = append(res, name)
		}
		return res, nil
	default:
		return nil, fmt.Errorf("invalid proxies type %T", v)
	}
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

func (airport *Airport) groupAddProxies(key string, proxies any) error {
	proxyNames, err := normalizeProxyNames(proxies)
	if err != nil {
		return err
	}

	for _, proxy := range proxyNames {
		if airport.Proxies.get(proxy) == nil {
			return fmt.Errorf("proxy %s not found", proxy)
		}
	}

	group := airport.Groups.get(key)
	if group == nil {
		group = YamlStrDict{"proxies": []string{}}
		airport.Groups.set(key, group)
	}

	groupProxies, ok := group["proxies"]
	if !ok {
		return fmt.Errorf("group %s has no 'proxies'", key)
	}

	groupProxiesL, err := normalizeProxyNames(groupProxies)
	if err != nil {
		return fmt.Errorf("group %s has invalid 'proxies': %w", key, err)
	}

	for _, proxy := range proxyNames {
		found := false
		for _, groupProxy := range groupProxiesL {
			if groupProxy == proxy {
				found = true
				break
			}
		}
		if !found {
			groupProxiesL = append(groupProxiesL, proxy)
		}
	}

	group["proxies"] = groupProxiesL
	return nil
}

func (airport *Airport) removeProxy(key string) {
	airport.Proxies.del(key)

	airport.Groups.each(func(_ string, group YamlStrDict) {
		groupProxies, ok := group["proxies"]
		if !ok {
			return
		}
		groupProxiesL, err := normalizeProxyNames(groupProxies)
		if err != nil {
			return
		}

		k := 0
		for idx, groupProxy := range groupProxiesL {
			if groupProxy != key {
				if k != idx {
					groupProxiesL[k] = groupProxy
				}
				k++
			}
		}
		group["proxies"] = groupProxiesL[:k]
	})
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
