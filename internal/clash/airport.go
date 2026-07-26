package clash

import (
	"fmt"
	"sort"
)

// AirportSpec is one upstream entry as declared in upstreams.yaml.
type AirportSpec struct {
	Name          string   `yaml:"name"`
	Urls          []string `yaml:"urls"`
	Ttl           int      `yaml:"ttl"`
	Tags          []string `yaml:"tag"`
	UseCacheOnErr bool     `yaml:"use-cache-on-err"`
	Enable        *bool    `yaml:"enable"`
}

// Enabled reports whether this upstream is selectable; upstreams are enabled
// unless "enable: false" is set explicitly.
func (as *AirportSpec) Enabled() bool {
	return as.Enable == nil || *as.Enable
}

// AllTags returns every tag a request may select this upstream by: its declared
// tags plus its own name and the implicit "all".
func (as *AirportSpec) AllTags() []string {
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

func (airport *Airport) renameProxy(key string, newKey string) error {
	if airport.Proxies.get(newKey) != nil {
		return fmt.Errorf("proxy %s already exists", newKey)
	}

	proxy := airport.Proxies.get(key)
	if proxy == nil {
		return fmt.Errorf("proxy %s not found", key)
	}

	airport.Proxies.del(key)
	airport.Proxies.set(newKey, proxy)
	return nil
}

func (airport *Airport) removeProxy(key string) {
	airport.Proxies.del(key)
}

// filterProxy drops every proxy for which keep returns false.
func (airport *Airport) filterProxy(keep func(YamlStrDict) bool) {
	toRemove := []string{}
	airport.Proxies.each(func(key string, proxy YamlStrDict) {
		if !keep(proxy) {
			toRemove = append(toRemove, key)
		}
	})
	for _, key := range toRemove {
		airport.removeProxy(key)
	}
}

func mergeProxies(from, to *Airport) {
	for _, key := range from.Proxies.keys() {
		old_key := key
		// Deterministic suffix (old_2, old_3, ...) so identical inputs always
		// produce identical names — a random suffix would make output unstable.
		for i := 2; to.Proxies.get(key) != nil; i++ {
			key = fmt.Sprintf("%s_%d", old_key, i)
		}
		if old_key != key {
			from.renameProxy(old_key, key)
		}
		to.Proxies.set(key, from.Proxies.get(key))
	}
}

func stackAirports(airports []*Airport) *Airport {
	merged := &Airport{Proxies: NewEmptyDictList()}

	for _, airport := range airports {
		mergeProxies(airport, merged)
	}

	return merged
}

// sortedAirportKeys returns the airport names in a stable order so that all
// passes over the airports map (conflict resolution, proxy collection, group
// building) produce deterministic, byte-stable output instead of leaking Go's
// random map iteration order into the generated config.
func sortedAirportKeys(airports map[string]*Airport) []string {
	keys := make([]string, 0, len(airports))
	for k := range airports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func resolveAirportNameConflicts(airports map[string]*Airport) {
	merged := &Airport{Proxies: NewEmptyDictList()}
	for _, name := range sortedAirportKeys(airports) {
		mergeProxies(airports[name], merged)
	}
}
