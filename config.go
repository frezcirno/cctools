package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

var PROXY_BLACKLIST = []string{"DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"}

func init() {
}

type AirportSpec struct {
	Name          string   `yaml:"name"`
	Urls          []string `yaml:"urls"`
	Ttl           int      `yaml:"ttl"`
	Enabled       bool     `yaml:"enabled"`
	Tags          []string `yaml:"tags"`
	UseCacheOnErr bool     `yaml:"use-cache-on-err"`
}

func (as *AirportSpec) tags() []string {
	tags := append(as.Tags, as.Name, "all")
	if as.Enabled {
		tags = append(tags, "default")
	}
	return tags
}

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
		groupProxiesL := groupProxies.([]interface{})
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

func (airport *Airport) groupAddProxies(key string, proxies []interface{}) error {
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
		groupProxiesL := groupProxies.([]interface{})

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

func randomStr(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func loadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open cache: %v", err)
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func download(url *url.URL, cache_key string, ttl time.Duration, postprocesser func([]byte) []byte, timeout int, use_cache_on_err bool) ([]byte, error) {
	if cache_key == "" {
		cache_key = fmt.Sprintf("%x", sha1.Sum([]byte(url.String())))
	}
	save_path := "./cache/" + cache_key
	log.Printf("Retrieving %s, cache %s", url, save_path)
	cache_ok := false

	if fi, err := os.Stat(save_path); err == nil {
		cache_ok = true
		now := time.Now()
		ctime := fi.ModTime()
		if ctime.After(now) {
			log.Printf("Clock changed, ignoring cache")
		} else if now.Sub(ctime) < ttl {
			return loadFile(save_path)
		}
	}

	var content []byte

	if url.Scheme == "file" {
		f, err := os.Open(url.Path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		content, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
	} else if url.Scheme == "base64" {
		var err error
		content, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(url.Host)))
		if err != nil {
			return nil, err
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
		if err != nil {
			log.Printf("Failed to request %s: %v", url, err)
			return nil, err
		}
		req.Header = http.Header{
			"User-Agent":                []string{USER_AGENT},
			"Accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"Cache-Control":             []string{"no-cache"},
			"Pragma":                    []string{"no-cache"},
			"Accept-Language":           []string{"zh-CN,zh;q=0.9"},
			"Sec-Fetch-Dest":            []string{"document"},
			"Sec-Fetch-Mode":            []string{"navigate"},
			"Sec-Fetch-Site":            []string{"none"},
			"Sec-Fetch-User":            []string{"?1"},
			"Upgrade-Insecure-Requests": []string{"1"},
			"sec-ch-ua":                 []string{"\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\""},
			"sec-ch-ua-mobile":          []string{"?0"},
			"sec-ch-ua-platform":        []string{"\"Windows\""},
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if cache_ok && use_cache_on_err {
				return loadFile(save_path)
			}
			if err == nil {
				err = fmt.Errorf("status code %d", resp.StatusCode)
			}
			log.Printf("Failed to retrieve %s: %v", url, err)
			return nil, err
		}

		content, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	if postprocesser != nil {
		content = postprocesser(content)
	}

	if _, err := os.LookupEnv("DISABLE_CACHE"); !err {
		os.MkdirAll("./cache", os.ModePerm)
		if f, err := os.Create(save_path); err == nil {
			defer f.Close()
			f.Write(content)
		}
	}

	return content, nil
}

func downloadUpstream(upstream *url.URL, upstream_name string, ttl int, timeout int, use_cache_on_err bool) (*Airport, error) {
	content, err := download(upstream, upstream_name, time.Duration(ttl)*time.Second, nil, timeout, use_cache_on_err)
	if err != nil {
		log.Printf("Failed to retrieve upstream %v: %v", upstream, err)
		return nil, err
	}

	var obj YamlStrDict
	if err := yaml.Unmarshal(content, &obj); err != nil {
		log.Printf("Failed to parse upstream %v: %v", upstream, err)
		return nil, err
	}

	_proxies, ok := obj["proxies"].([]interface{})
	if !ok {
		err := fmt.Errorf("proxies not found")
		log.Printf("Failed to parse upstream: %v %v", upstream, err)
		return nil, err
	}
	proxies := NewDictList(_proxies)
	_groups, ok := obj["proxy-groups"].([]interface{})
	if !ok {
		err := fmt.Errorf("proxy-groups not found")
		log.Printf("Failed to parse upstream %v: %v", upstream, err)
		return nil, err
	}
	groups := NewDictList(_groups)

	airport := Airport{proxies, groups}

	airport.filterProxy(func(m YamlStrDict) bool {
		for _, b := range PROXY_BLACKLIST {
			if _, ok := m["name"]; ok {
				if strings.Contains(m["name"].(string), b) {
					return false
				}
			}
		}
		return true
	})

	return &airport, nil
}

func mergeProxies(from, to Airport) {
	for _, key := range from.Proxies.keys() {
		old_key := key
		for to.Proxies.get(key) != nil {
			key = old_key + "_" + randomStr(3)
		}
		if old_key != key {
			from.renameProxy(old_key, key)
		}
		to.Proxies.set(key, from.Proxies.get(key))
	}
}

func mergeGroups(from, to Airport) {
	for key := range from.Groups {
		old_key := key
		for to.Groups.get(key) != nil {
			key = old_key + "_" + randomStr(3)
		}
		if old_key != key {
			from.renameGroup(old_key, key)
		}
		to.Groups.set(key, nil)
	}
}

func stackAirports(airports []Airport) Airport {
	merged := NewAirport()

	for _, airport := range airports {
		mergeProxies(airport, merged)
		for key, group := range airport.Groups {
			merged.groupAddProxies(key, group["proxies"].([]interface{}))
		}
	}

	return merged
}

func renameUpstreams(airports map[string]Airport) {
	merged := NewAirport()
	for _, airport := range airports {
		mergeProxies(airport, merged)
		mergeGroups(airport, merged)
	}
}

type Platform string

const (
	Windows Platform = "windows"
	Linux   Platform = "linux"
	Android Platform = "android"
	Darwin  Platform = "darwin"
	Other   Platform = "other"
)

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

type Config struct {
	Template  map[string]interface{}
	Upstreams map[string]AirportSpec

	Upstream             []string
	Organizer            []string
	TopSelect            []string
	KeepUpstreamSelector bool

	PortProxy bool
	Bind      string
	HttpPort  int
	SocksPort int
	MixedPort int

	TransProxy bool
	RedirPort  int
	TproxyPort int

	AllowLan               bool
	ExternalControllerType ExternalControllerType
	ExternalControllerAddr string
	Secret                 string

	Dns               bool
	DnsListen         string
	EnhancedMode      string
	DefaultNameserver []string
	Nameserver        []string
	Fallback          []string
	NameserverPolicy  map[string]string

	Tun      bool
	TunStack string

	RuleProviderTransform RuleProviderTransform
	CustomRules           []string
	Platform              Platform
}

func (c *Config) Validate() error {
	if c.Upstreams == nil {
		return fmt.Errorf("need upstreams")
	}

	// for _, upstream := range config.Upstream {
	// 	if _, ok := config.AllUpstream[upstream]; !ok {
	// 		return fmt.Errorf("Upstream %s not found", upstream)
	// 	}
	// }

	return nil
}

func (c *Config) upstreams() []AirportSpec {
	// select all upstreams matching tags
	selected := []AirportSpec{}
	userTags := c.Upstream
	if len(userTags) == 0 {
		userTags = []string{"default"}
	}
	for _, upstream := range c.Upstreams {
		matched := false
		for _, userTag := range userTags {
			for _, upstreamTag := range upstream.tags() {
				if userTag == upstreamTag {
					selected = append(selected, upstream)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}
	return selected
}

func (c *Config) contains_group(key string) bool {
	for _, group := range c.Organizer {
		if group == key {
			return true
		}
	}
	return false
}

func (c *Config) generate(r *http.Request) (YamlStrDict, error) {
	customSelectors := []string{}
	if tpl_rules, ok := c.Template["rules"]; ok {
		presetChains := map[string]string{
			"DIRECT":   "DIRECT",
			"REJECT":   "REJECT",
			"PROXY":    "PROXY",
			"UDP":      "UDP",
			"FALLBACK": "FALLBACK",
			"CNSITE":   "CNSITE",
		}
		for _, rule := range tpl_rules.([]interface{}) {
			rulesegs := strings.Split(rule.(string), ",")
			if len(rulesegs) >= 3 {
				chain := rulesegs[2]
				if _, ok := presetChains[chain]; !ok {
					presetChains[chain] = chain
					customSelectors = append(customSelectors, chain)
				}
			}
		}
	}
	// reorder
	allSelectors := append(append([]string{"PROXY"}, customSelectors...), "UDP", "FALLBACK", "CNSITE")

	if c.PortProxy {
		c.Template["allow-lan"] = c.AllowLan
		c.Template["bind-address"] = c.Bind

		if c.HttpPort != 0 {
			c.Template["port"] = c.HttpPort
		}
		if c.SocksPort != 0 {
			c.Template["socks-port"] = c.SocksPort
		}
		if c.MixedPort != 0 {
			c.Template["mixed-port"] = c.MixedPort
		}
	}

	if c.TransProxy {
		if c.RedirPort == 0 {
			c.RedirPort = 7983
		}
		if c.TproxyPort == 0 {
			c.TproxyPort = 7894
		}

		if c.RedirPort != 0 {
			c.Template["redir-port"] = c.RedirPort
		}
		if c.TproxyPort != 0 {
			c.Template["tproxy-port"] = c.TproxyPort
		}
	}

	if c.ExternalControllerType != NONE {
		if c.ExternalControllerType == HTTP {
			c.Template["external-controller"] = c.ExternalControllerAddr
		} else if c.ExternalControllerType == HTTPS {
			c.Template["external-controller-tls"] = c.ExternalControllerAddr
		} else if c.ExternalControllerType == UNIX {
			c.Template["external-controller-unix"] = c.ExternalControllerAddr
		}
	}

	c.Template["secret"] = c.Secret

	if c.Dns {
		dns := c.Template["dns"].(map[interface{}]interface{})
		dns["enable"] = true
		dns["listen"] = c.DnsListen
		dns["enhanced-mode"] = c.EnhancedMode

		dns["default-nameserver"] = c.DefaultNameserver
		dns["nameserver"] = c.Nameserver
		dns["fallback"] = c.Fallback
		dns["nameserver-policy"] = c.NameserverPolicy // .(map[interface{}]interface{})["+.zju.edu.cn"] = dhcpdns
	}

	if c.Tun {
		tun := c.Template["tun"].(map[interface{}]interface{})
		tun["enable"] = true
		tun["stack"] = c.TunStack
		if c.Platform == Windows {
			tun["auto-redir"] = false
		}
	}

	// retrieve upstream yamls
	type pair struct {
		k string
		v Airport
	}
	airports := map[string]Airport{}
	_upstreams := c.upstreams()
	ch := make(chan pair, len(_upstreams))
	defer close(ch)
	for _, upstream := range _upstreams {
		_copy := upstream
		go func() {
			airports := []Airport{}
			for idx, _url := range _copy.Urls {
				u, err := url.Parse(_url)
				if err != nil {
					continue
				}
				airport, err := downloadUpstream(u, fmt.Sprintf("upstream-%s-%d.yaml", _copy.Name, idx), _copy.Ttl, 10, _copy.UseCacheOnErr)
				if err != nil {
					continue
				}
				airports = append(airports, *airport)
			}
			ch <- pair{_copy.Name, stackAirports(airports)}
		}()
	}
	for range _upstreams {
		p := <-ch
		airports[p.k] = p.v
	}

	// rename streams to avoid name crash
	renameUpstreams(airports)

	// proxies
	all_proxies := DictList{}
	for _, airport := range airports {
		all_proxies.update(airport.Proxies)
	}
	c.Template["proxies"] = all_proxies.values()

	// groups
	instance_urltest_groups := []YamlStrDict{}

	key := "all"

	if len(all_proxies) > 0 {
		instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
			"name":      key,
			"type":      "url-test",
			"proxies":   all_proxies.keys(),
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  86400,
			"tolerance": 100,
		})
	}

	_cn := []string{}
	_tw := []string{}
	_oversea := []string{}
	_udp := []string{}

	for _, proxy := range all_proxies {
		if isCN(proxy) {
			_cn = append(_cn, proxy["name"].(string))
		}
		if isTW(proxy) {
			_tw = append(_tw, proxy["name"].(string))
		}
		if isOversea(proxy) {
			_oversea = append(_oversea, proxy["name"].(string))
		}
		if isUDP(proxy) {
			_udp = append(_udp, proxy["name"].(string))
		}
	}

	if c.contains_group("cn") && len(_cn) > 0 {
		sort.Strings(_cn)

		instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
			"name":      fmt.Sprintf("%s-cn", key),
			"type":      "url-test",
			"proxies":   _cn,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  86400,
			"tolerance": 100,
		})
	}

	if c.contains_group("tw") && len(_tw) > 0 {
		sort.Strings(_tw)

		instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
			"name":      fmt.Sprintf("%s-tw", key),
			"type":      "url-test",
			"proxies":   _tw,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  86400,
			"tolerance": 100,
		})
	}

	if c.contains_group("oversea") && len(_oversea) > 0 {
		sort.Strings(_oversea)

		instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
			"name":      fmt.Sprintf("%s-oversea", key),
			"type":      "url-test",
			"proxies":   _oversea,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  86400,
			"tolerance": 100,
		})
	}

	if c.contains_group("udp") && len(_udp) > 0 {
		sort.Strings(_udp)

		instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
			"name":      fmt.Sprintf("%s-udp", key),
			"type":      "url-test",
			"proxies":   _udp,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  86400,
			"tolerance": 100,
		})
	}

	for name, airport := range airports {
		airport_proxies := airport.Proxies

		if len(airport.Proxies) > 0 {
			airport_proxies_keys := airport_proxies.keys()
			sort.Strings(airport_proxies_keys)

			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      name,
				"type":      "url-test",
				"proxies":   airport_proxies_keys,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  86400,
				"tolerance": 100,
			})
		}

		_cn := []string{}
		_tw := []string{}
		_oversea := []string{}
		_udp := []string{}

		for _, proxy := range airport_proxies {
			if isCN(proxy) {
				_cn = append(_cn, proxy["name"].(string))
			}
			if isTW(proxy) {
				_tw = append(_tw, proxy["name"].(string))
			}
			if isOversea(proxy) {
				_oversea = append(_oversea, proxy["name"].(string))
			}
			if isUDP(proxy) {
				_udp = append(_udp, proxy["name"].(string))
			}
		}

		if c.contains_group("cn") && len(_cn) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-cn", name),
				"type":      "url-test",
				"proxies":   _cn,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  86400,
				"tolerance": 100,
			})
		}

		if c.contains_group("tw") && len(_tw) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-tw", name),
				"type":      "url-test",
				"proxies":   _tw,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  86400,
				"tolerance": 100,
			})
		}

		if c.contains_group("oversea") && len(_oversea) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-oversea", name),
				"type":      "url-test",
				"proxies":   _oversea,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  86400,
				"tolerance": 100,
			})
		}

		if c.contains_group("udp") && len(_udp) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-udp", name),
				"type":      "url-test",
				"proxies":   _udp,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  86400,
				"tolerance": 100,
			})
		}
	}

	// selector groups
	instance_groups_keys := []string{}
	for _, g := range instance_urltest_groups {
		instance_groups_keys = append(instance_groups_keys, g["name"].(string))
	}
	instance_selector_groups := []YamlStrDict{}
	for _, selector := range append(allSelectors, c.TopSelect...) {
		var _p []string

		if selector == "PROXY" {
			_p = append(instance_groups_keys, "DIRECT")
		} else if selector == "FALLBACK" {
			_p = []string{"PROXY", "DIRECT"}
		} else if selector == "CNSITE" {
			_p = []string{"DIRECT", "PROXY"}
		} else if selector == "UDP" {
			_p = []string{"PROXY", "DIRECT"}
		} else {
			_p = append([]string{"PROXY"}, instance_groups_keys...)
			_p = append(_p, "DIRECT")
		}

		instance_selector_groups = append(instance_selector_groups, YamlStrDict{
			"name":    selector,
			"type":    "select",
			"proxies": _p,
		})
	}

	c.Template["proxy-groups"] = append(instance_selector_groups, instance_urltest_groups...)

	if c.RuleProviderTransform == RPT_INLINE {
		rule_providers := c.Template["rule-providers"].(map[interface{}]interface{})
		delete(c.Template, "rule-providers")

		rule_provider_map := map[string]YamlStrDict{}
		for rule_set_name, rule_provider := range rule_providers {
			rule_set_name := rule_set_name.(string)
			rule_provider := rule_provider.(map[interface{}]interface{})

			behavior := rule_provider["behavior"].(string)
			url, err := url.Parse(rule_provider["url"].(string))
			if err != nil {
				log.Printf("Failed to parse rule provider url: %v", err)
				return nil, err
			}

			content, err := download(url, fmt.Sprintf("rule-%s.yaml", rule_set_name), 24*time.Hour, nil, 10, true)
			if err != nil {
				log.Printf("Failed to retrieve rule provider: %v", err)
				return nil, err
			}

			if err := yaml.Unmarshal(content, &rule_provider); err != nil {
				log.Printf("Failed to parse rule provider: %v", err)
				return nil, err
			}

			rule_provider_map[rule_set_name] = YamlStrDict{
				"name":     rule_set_name,
				"behavior": behavior,
				"patterns": rule_provider["payload"],
			}
		}

		rules := []string{}
		for _, rule := range c.Template["rules"].([]interface{}) {
			rule := rule.(string)
			rule_segs := strings.Split(rule, ",")

			if len(rule_segs) < 2 {
				continue
			}
			if rule_segs[0] != "RULE-SET" {
				rules = append(rules, rule)
				continue
			}

			rule_set_name := rule_segs[1]
			rule_provider, ok := rule_provider_map[rule_set_name]
			if !ok {
				continue
			}

			rule_action := rule_segs[2]
			behavior := rule_provider["behavior"].(string)

			for _, pattern := range rule_provider["patterns"].([]interface{}) {
				pattern := pattern.(string)
				new_rule := ""
				if strings.HasPrefix(pattern, "DOMAIN") || strings.HasPrefix(pattern, "IP-CIDR") || behavior == "classical" {
					if strings.Contains(pattern, ",no-resolve") {
						pattern = strings.Replace(pattern, ",no-resolve", "", 1)
						new_rule = fmt.Sprintf("%s,%s,no-resolve", pattern, rule_action)
					} else {
						new_rule = fmt.Sprintf("%s,%s", pattern, rule_action)
					}
				} else if behavior == "domain" {
					new_rule = fmt.Sprintf("DOMAIN,%s,%s", pattern, rule_action)
				} else if behavior == "ipcidr" {
					new_rule = fmt.Sprintf("IP-CIDR,%s,%s", pattern, rule_action)
				} else {
					log.Printf("Unknown behavior: %s", behavior)
					continue
				}
				rules = append(rules, new_rule)
			}
		}
		c.Template["rules"] = rules
	} else if c.RuleProviderTransform == RPT_PROXY {
		rule_providers := c.Template["rule-providers"].(map[interface{}]interface{})
		for rule_set_name, rule_provider := range rule_providers {
			rule_set_name := rule_set_name.(string)
			rule_provider := rule_provider.(map[interface{}]interface{})

			proxyUrl := fmt.Sprintf("%s://%s/rule-providers?rule-set=%s", Scheme(r), HostAndPort(r), rule_set_name)
			rule_provider["url"] = proxyUrl
		}
	}

	return c.Template, nil
}

func Scheme(r *http.Request) string {
	// Can't use `r.Request.URL.Scheme`
	// See: https://groups.google.com/forum/#!topic/golang-nuts/pMUkBlQBDF0
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if scheme := r.Header.Get("X-Forwarded-Protocol"); scheme != "" {
		return scheme
	}
	if ssl := r.Header.Get("X-Forwarded-Ssl"); ssl == "on" {
		return "https"
	}
	if scheme := r.Header.Get("X-Url-Scheme"); scheme != "" {
		return scheme
	}
	if scheme := r.Header.Get("X-Scheme"); scheme != "" {
		return scheme
	}
	return "http"
}

func HostAndPort(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = r.Header.Get("Host")
	}
	return host
}
