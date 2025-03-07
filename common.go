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
	Default       bool     `yaml:"default"`
	Tags          []string `yaml:"tags"`
	UseCacheOnErr bool     `yaml:"use-cache-on-err"`
}

func (as *AirportSpec) tags() []string {
	tags := append(as.Tags, as.Name, "all")
	if as.Default {
		tags = append(tags, "default")
	}
	return tags
}

// Airport
type Airport struct {
	Proxies DictList `yaml:"proxies"`
	Groups  DictList `yaml:"groups"`
}

func NewAirport() Airport {
	return Airport{
		Proxies: DictList{},
		Groups:  DictList{},
	}
}

func (airport *Airport) renameProxy(key string, new_key string) error {
	// new_key should not exist
	if airport.Proxies.get(new_key) != nil {
		return fmt.Errorf("proxy %s already exists", new_key)
	}

	proxy := airport.Proxies.get(key)
	if proxy == nil {
		return fmt.Errorf("proxy %s not found", key)
	}

	delete(airport.Proxies, key)
	airport.Proxies.set(new_key, proxy)

	for _, group := range airport.Groups {
		groupProxies, ok := group["proxies"]
		if !ok {
			continue
		}
		groupProxiesL := groupProxies.([]any)
		for idx, groupProxy := range groupProxiesL {
			if groupProxy == key {
				groupProxiesL[idx] = new_key
			}
		}
	}
	return nil
}

func (airport *Airport) renameGroup(key string, new_key string) error {
	group := airport.Groups.get(key)
	if group == nil {
		return fmt.Errorf("group %s not found", key)
	}

	delete(airport.Groups, key)
	airport.Groups.set(new_key, group)

	return nil
}

func (airport *Airport) groupAddProxies(key string, proxies []any) error {
	// validate proxies
	for _, proxy := range proxies {
		if airport.Proxies.get(proxy.(string)) == nil {
			return fmt.Errorf("proxy %s not found", proxy)
		}
	}

	// ensure group
	group := airport.Groups.get(key)
	if group == nil {
		group = YamlStrDict{}
		airport.Groups.set(key, group)
	}

	groupProxies, ok := group["proxies"]
	if !ok {
		return fmt.Errorf("group %s has no 'proxies'", key)
	}

	groupProxiesL := groupProxies.([]string)

	// dedup add
	for _, proxy := range proxies {
		found := false
		for _, groupProxy := range groupProxiesL {
			if groupProxy == proxy {
				found = true
				break
			}
		}
		if !found {
			groupProxiesL = append(groupProxiesL, proxy.(string))
		}
	}

	group["proxies"] = groupProxiesL
	return nil
}

func (airport *Airport) removeProxy(key string) {
	delete(airport.Proxies, key)

	for _, group := range airport.Groups {
		groupProxies, ok := group["proxies"]
		if !ok {
			continue
		}
		groupProxiesL := groupProxies.([]any)

		// avoid memory reallocation
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
	}
}

func (airport *Airport) filterProxy(filter func(YamlStrDict) bool) {
	for key, proxy := range airport.Proxies {
		if !filter(proxy) {
			airport.removeProxy(key)
		}
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
