package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const DEFAULT_HTTP_PORT = 7890
const DEFAULT_SOCKS_PORT = 7891
const DEFAULT_REDIR_PORT = 7892
const DEFAULT_TPROXY_PORT = 7894
const DEFAULT_MIXED_PORT = 7890
const DEFAULT_CONTROLLER_PORT = 9090
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

var PROXY_BLACKLIST = []string{"DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"}

var REGEXP *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong|tw|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)`)
var TEMPLATE []byte
var PRESET_CHAINS []string

type (
	YamlStrDict map[string]interface{}
)

func init() {
	rand.Seed(time.Now().UnixNano())

	f, err := os.Open("./template.yaml")
	if err != nil {
		log.Fatalf("Failed to open template: %v", err)
	}
	defer f.Close()

	TEMPLATE, err = io.ReadAll(f)
	if err != nil {
		log.Fatalf("Failed to read template: %v", err)
	}

	var _tmp YamlStrDict
	err = yaml.Unmarshal(TEMPLATE, &_tmp)
	if err != nil {
		log.Fatalf("Failed to load template: %v", err)
	}

	PRESET_CHAINS = []string{"PROXY", "UDP", "FALLBACK"}
	if tpl_rules, ok := _tmp["rules"]; ok {
		for _, rule := range tpl_rules.([]interface{}) {
			rulesegs := strings.Split(rule.(string), ",")
			if len(rulesegs) >= 3 {
				chain := rulesegs[2]
				if chain != "DIRECT" && chain != "REJECT" {
					exists := false
					for _, preset := range PRESET_CHAINS {
						if preset == chain {
							exists = true
							break
						}
					}
					if !exists {
						PRESET_CHAINS = append(PRESET_CHAINS, chain)
					}
				}
			}
		}

		// reorder
		PRESET_CHAINS = append(append([]string{"PROXY"}, PRESET_CHAINS[3:]...), "UDP", "FALLBACK")
	}
}

type Attitude int

const (
	NO Attitude = iota
	YES
	NA
)

type Mode string

const (
	PROXY Mode = "proxy"
	TUN   Mode = "tun"
	REDIR Mode = "redir"
)

type DictList map[string]YamlStrDict

func NewDictList(in []interface{}) DictList {
	dl := DictList{}
	for _, elm := range in {
		elm := elm.(map[interface{}]interface{})
		name := elm["name"].(string)
		value := YamlStrDict{}
		for k, v := range elm {
			value[k.(string)] = v
		}
		dl[name] = value
	}
	return dl
}

func (dl *DictList) get(key string) YamlStrDict {
	if v, ok := (*dl)[key]; ok {
		return v
	}
	return nil
}

func (dl *DictList) set(key string, value YamlStrDict) {
	if value != nil {
		value["name"] = key
	}
	(*dl)[key] = value
}

func (dl *DictList) update(rhs DictList) {
	for k, v := range rhs {
		(*dl)[k] = v
	}
}

func (dl *DictList) keys() (res []string) {
	for k := range *dl {
		res = append(res, k)
	}
	return
}

func (dl *DictList) values() (res []YamlStrDict) {
	for _, v := range *dl {
		res = append(res, v)
	}
	return
}

type UpstreamSpec struct {
	Name          string   `yaml:"name"`
	Urls          []string `yaml:"urls"`
	Ttl           int      `yaml:"ttl"`
	Enabled       bool     `yaml:"enabled"`
	Tags          []string `yaml:"tags"`
	UseCacheOnErr bool     `yaml:"use-cache-on-err"`
}

func (us *UpstreamSpec) tags() []string {
	tags := append(us.Tags, us.Name, "all")
	if us.Enabled {
		tags = append(tags, "default")
	}
	return tags
}

type UpstreamData struct {
	Proxies DictList `yaml:"proxies"`
	Groups  DictList `yaml:"groups"`
}

func NewUpstreamData() UpstreamData {
	return UpstreamData{
		Proxies: DictList{},
		Groups:  DictList{},
	}
}

func (ud *UpstreamData) rename_proxy(key string, new_key string) error {
	// new_key should not exist
	if ud.Proxies.get(new_key) != nil {
		return fmt.Errorf("proxy %s already exists", new_key)
	}

	proxy := ud.Proxies.get(key)
	if proxy == nil {
		return fmt.Errorf("proxy %s not found", key)
	}

	delete(ud.Proxies, key)
	ud.Proxies.set(new_key, proxy)

	for _, group := range ud.Groups {
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

func (ud *UpstreamData) rename_group(key string, new_key string) error {
	group := ud.Groups.get(key)
	if group == nil {
		return fmt.Errorf("group %s not found", key)
	}

	delete(ud.Groups, key)
	ud.Groups.set(new_key, group)

	return nil
}

func (ud *UpstreamData) group_add_proxies(key string, proxies []interface{}) error {
	// validate proxies
	for _, proxy := range proxies {
		if ud.Proxies.get(proxy.(string)) == nil {
			return fmt.Errorf("proxy %s not found", proxy)
		}
	}

	// ensure group
	group := ud.Groups.get(key)
	if group == nil {
		group = YamlStrDict{}
		ud.Groups.set(key, group)
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

func (ud *UpstreamData) remove_proxy(key string) {
	delete(ud.Proxies, key)

	for _, group := range ud.Groups {
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

func (ud *UpstreamData) filter_proxy(filter func(YamlStrDict) bool) {
	for key, proxy := range ud.Proxies {
		if !filter(proxy) {
			ud.remove_proxy(key)
		}
	}
}

func random_str(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func load_file(path string) ([]byte, error) {
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
			return load_file(save_path)
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
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			return nil, err
		}
		req.Header = http.Header{
			"User-Agent": []string{USER_AGENT},
			"Accept": []string{
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"Cache-Control": []string{"no-cache"},
			"Pragma":        []string{"no-cache"},
			"Accept-Language": []string{
				"zh-CN,zh;q=0.9"},
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
				return load_file(save_path)
			}
			if err == nil {
				err = fmt.Errorf("status code %d", resp.StatusCode)
			}
			log.Printf("Failed to retrieve upstream: %v", err)
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

func download_upstream(upstream *url.URL, upstream_name string, ttl int, timeout int, use_cache_on_err bool) (*UpstreamData, error) {
	content, err := download(upstream, upstream_name, time.Duration(ttl)*time.Second, nil, timeout, use_cache_on_err)
	if err != nil {
		log.Printf("Failed to retrieve upstream: %v", err)
		return nil, err
	}

	var obj YamlStrDict
	if err := yaml.Unmarshal(content, &obj); err != nil {
		log.Printf("Failed to parse upstream: %v", err)
		return nil, err
	}

	_proxies, ok := obj["proxies"].([]interface{})
	if !ok {
		log.Printf("Failed to parse upstream: %v", err)
		return nil, err
	}
	proxies := NewDictList(_proxies)
	_groups, ok := obj["proxy-groups"].([]interface{})
	if !ok {
		log.Printf("Failed to parse upstream: %v", err)
		return nil, err
	}
	groups := NewDictList(_groups)

	ud := UpstreamData{proxies, groups}

	ud.filter_proxy(func(m YamlStrDict) bool {
		for _, b := range PROXY_BLACKLIST {
			if _, ok := m["name"]; ok {
				if strings.Contains(m["name"].(string), b) {
					return false
				}
			}
		}
		return true
	})

	return &ud, nil
}

func merge_proxies(from, to UpstreamData) {
	for _, key := range from.Proxies.keys() {
		old_key := key
		for to.Proxies.get(key) != nil {
			key = old_key + "_" + random_str(3)
		}
		if old_key != key {
			from.rename_proxy(old_key, key)
		}
		to.Proxies.set(key, from.Proxies.get(key))
	}
}

func merge_groups(from, to UpstreamData) {
	for key := range from.Groups {
		old_key := key
		for to.Groups.get(key) != nil {
			key = old_key + "_" + random_str(3)
		}
		if old_key != key {
			from.rename_group(old_key, key)
		}
		to.Groups.set(key, nil)
	}
}

func stack_upstreams(upstreams []UpstreamData) UpstreamData {
	merged := NewUpstreamData()

	for _, upstream := range upstreams {
		merge_proxies(upstream, merged)
		for key, group := range upstream.Groups {
			merged.group_add_proxies(key, group["proxies"].([]interface{}))
		}
	}

	return merged
}

func rename_upstreams(upstreams map[string]UpstreamData) {
	merged := NewUpstreamData()
	for _, upstream := range upstreams {
		merge_proxies(upstream, merged)
		merge_groups(upstream, merged)
	}
}

type Config struct {
	Mode                 Mode
	Trusted              bool
	Port                 int
	SocksPort            int
	RedirPort            int
	TproxyPort           int
	MixedPort            int
	ControllerPort       int
	Secret               string
	Dns                  Attitude
	DnsListen            string
	DnsPort              int
	Eth                  string
	KeepUpstreamSelector bool
	Group                []string
	AllUpstream          map[string]UpstreamSpec
	Selector             []string
	Upstream             []string
	NoRuleProviders      bool
	Platform             string
}

func (c *Config) Validate() error {
	if c.Mode != PROXY && c.Mode != TUN && c.Mode != REDIR {
		return fmt.Errorf("invalid mode %s", c.Mode)
	}

	if c.Mode != PROXY && c.Eth == "" {
		return fmt.Errorf("eth is required in %s mode", c.Mode)
	}

	if c.AllUpstream == nil {
		return fmt.Errorf("need upstreams")
	}

	if c.Mode != PROXY {
		if c.Secret != "" {
			return fmt.Errorf("secret is not recommended in %s mode", c.Mode)
		}
	}

	if c.Mode == PROXY {
		if c.Port == 0 && c.SocksPort == 0 && c.MixedPort == 0 {
			return fmt.Errorf("need at least one of port, socks-port or mixed-port")
		}
	}

	// for _, upstream := range config.Upstream {
	// 	if _, ok := config.AllUpstream[upstream]; !ok {
	// 		return fmt.Errorf("Upstream %s not found", upstream)
	// 	}
	// }

	return nil
}

func (c *Config) upstreams() []UpstreamSpec {
	// select all upstreams matching tags
	selected := []UpstreamSpec{}
	userTags := c.Upstream
	if len(userTags) == 0 {
		userTags = []string{"default"}
	}
	for _, upstream := range c.AllUpstream {
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

func (c *Config) trusted() bool {
	// in trusted mode, we bind to all interfaces and allow LAN, and disable secret
	return c.Mode != PROXY || c.Trusted
}

func (c *Config) controllerPort() int {
	if c.ControllerPort != 0 {
		return c.ControllerPort
	}
	return DEFAULT_CONTROLLER_PORT
}

func (c *Config) secret() string {
	if c.Secret != "" {
		return c.Secret
	}
	if c.trusted() {
		return ""
	}
	c.Secret = random_str(16)
	return c.Secret
}

func (c *Config) dns() bool {
	return c.Dns == YES || (c.Dns == NA && c.Mode != PROXY)
}

func (c *Config) dns_listen() string {
	if c.DnsListen != "" {
		return c.DnsListen
	}
	if c.trusted() {
		return "*"
	}
	return "127.0.0.1"
}

func (c *Config) dns_port() int {
	if c.DnsPort != 0 {
		return c.DnsPort
	}
	return 53
}

func (c *Config) dns_bind() string {
	return fmt.Sprintf("%s:%d", c.dns_listen(), c.dns_port())
}

func (c *Config) contains_group(key string) bool {
	for _, group := range c.Group {
		if group == key {
			return true
		}
	}
	return false
}

func (c *Config) generate() (YamlStrDict, error) {
	instance := YamlStrDict{}
	if err := yaml.Unmarshal(TEMPLATE, &instance); err != nil {
		return nil, err
	}

	if c.Mode == PROXY {
		if c.MixedPort == 0 {
			if c.Port == 0 {
				c.Port = DEFAULT_HTTP_PORT
			}
			if c.SocksPort == 0 {
				c.SocksPort = DEFAULT_SOCKS_PORT
			}
		}
	} else if c.Mode == REDIR {
		if c.RedirPort == 0 {
			c.RedirPort = DEFAULT_REDIR_PORT
		}
		if c.TproxyPort == 0 {
			c.TproxyPort = DEFAULT_TPROXY_PORT
		}
	}

	if c.Port != 0 {
		instance["port"] = c.Port
	}
	if c.SocksPort != 0 {
		instance["socks-port"] = c.SocksPort
	}
	if c.MixedPort != 0 {
		instance["mixed-port"] = c.MixedPort
	}
	if c.RedirPort != 0 {
		instance["redir-port"] = c.RedirPort
	}
	if c.TproxyPort != 0 {
		instance["tproxy-port"] = c.TproxyPort
	}

	if c.trusted() {
		instance["allow-lan"] = true
		instance["bind-address"] = "*"
	} else {
		instance["allow-lan"] = false
		instance["bind-address"] = "127.0.0.1"
	}
	instance["external-controller"] = fmt.Sprintf("127.0.0.1:%d", c.controllerPort())
	instance["secret"] = c.secret()

	if c.dns() {
		dns := instance["dns"].(map[interface{}]interface{})
		dns["enable"] = true
		dns["listen"] = c.dns_bind()
		dns["enhanced-mode"] = "fake-ip"
		if c.Mode != PROXY {
			dhcpdns := fmt.Sprintf("dhcp://%s", c.Eth)
			dns["nameserver"] = append(dns["nameserver"].([]interface{}), dhcpdns)
			dns["nameserver-policy"].(map[interface{}]interface{})["+.zju.edu.cn"] = dhcpdns
		}
	}

	if c.Mode == TUN {
		tun := instance["tun"].(map[interface{}]interface{})
		tun["enable"] = true
		if !c.dns() {
			tun["dns-hijack"] = []string{}
		}
		if c.Platform == "windows" {
			tun["stack"] = "gvisor"
			tun["auto-redir"] = false
		}
	}

	// retrieve upstream yamls
	type pair struct {
		k string
		v UpstreamData
	}
	uds := map[string]UpstreamData{}
	_upstreams := c.upstreams()
	ch := make(chan pair, len(_upstreams))
	defer close(ch)
	for _, upstream := range _upstreams {
		_copy := upstream
		go func() {
			uds := []UpstreamData{}
			for idx, _url := range _copy.Urls {
				u, err := url.Parse(_url)
				if err != nil {
					continue
				}
				ud, err := download_upstream(u, fmt.Sprintf("upstream-%s-%d.yaml", _copy.Name, idx), _copy.Ttl, 10, _copy.UseCacheOnErr)
				if err != nil {
					continue
				}
				uds = append(uds, *ud)
			}
			ch <- pair{_copy.Name, stack_upstreams(uds)}
		}()
	}
	for range _upstreams {
		p := <-ch
		uds[p.k] = p.v
	}

	// rename streams avoid crash
	rename_upstreams(uds)

	// proxies
	instance_proxies := DictList{}
	for _, ud := range uds {
		instance_proxies.update(ud.Proxies)
	}
	instance_proxies_keys := instance_proxies.keys()
	instance["proxies"] = instance_proxies.values()

	// groups
	instance_groups := []YamlStrDict{}

	key := "all"
	if len(instance_proxies_keys) > 0 {
		instance_groups = append(instance_groups, YamlStrDict{
			"name":      key,
			"type":      "url-test",
			"proxies":   instance_proxies_keys,
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  300,
			"tolerance": 100,
		})
	}
	if c.contains_group("cn") || c.contains_group("oversea") {
		_p := []string{}
		_n := []string{}
		for _, key := range instance_proxies_keys {
			if REGEXP.MatchString(key) {
				_p = append(_p, key)
			} else {
				_n = append(_n, key)
			}
		}

		if c.contains_group("cn") && len(_p) > 0 {
			instance_groups = append(instance_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-cn", key),
				"type":      "url-test",
				"proxies":   _p,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}

		if c.contains_group("oversea") && len(_n) > 0 {
			instance_groups = append(instance_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-oversea", key),
				"type":      "url-test",
				"proxies":   _n,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}
	}

	if c.contains_group("udp") {
		_p := []string{}
		for _, proxy := range instance_proxies {
			if _, ok := proxy["udp"].(string); ok {
				_p = append(_p, proxy["name"].(string))
			}
		}
		if len(_p) > 0 {
			instance_groups = append(instance_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-udp", key),
				"type":      "url-test",
				"proxies":   _p,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}
	}

	for key, ud := range uds {
		ud_proxies := ud.Proxies
		ud_proxies_keys := ud.Proxies.keys()

		if len(ud_proxies_keys) > 0 {
			instance_groups = append(instance_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-all", key),
				"type":      "url-test",
				"proxies":   ud_proxies_keys,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}

		if c.contains_group("cn") || c.contains_group("oversea") {
			_p := []string{}
			_n := []string{}
			for _, key := range ud_proxies_keys {
				if REGEXP.MatchString(key) {
					_p = append(_p, key)
				} else {
					_n = append(_n, key)
				}
			}

			if c.contains_group("cn") && len(_p) > 0 {
				instance_groups = append(instance_groups, YamlStrDict{
					"name":      fmt.Sprintf("%s-cn", key),
					"type":      "url-test",
					"proxies":   _p,
					"url":       "http://www.gstatic.com/generate_204",
					"interval":  300,
					"tolerance": 100,
				})
			}

			if c.contains_group("oversea") && len(_n) > 0 {
				instance_groups = append(instance_groups, YamlStrDict{
					"name":      fmt.Sprintf("%s-oversea", key),
					"type":      "url-test",
					"proxies":   _n,
					"url":       "http://www.gstatic.com/generate_204",
					"interval":  300,
					"tolerance": 100,
				})
			}
		}

		if c.contains_group("udp") {
			_p := []string{}
			for _, proxy := range ud_proxies {
				if _, ok := proxy["udp"].(string); ok {
					_p = append(_p, proxy["name"].(string))
				}
			}
			if len(_p) > 0 {
				instance_groups = append(instance_groups, YamlStrDict{
					"name":      fmt.Sprintf("%s-udp", key),
					"type":      "url-test",
					"proxies":   _p,
					"url":       "http://www.gstatic.com/generate_204",
					"interval":  300,
					"tolerance": 100,
				})
			}
		}
	}

	// chains
	instance_groups_keys := []string{}
	for _, g := range instance_groups {
		instance_groups_keys = append(instance_groups_keys, g["name"].(string))
	}
	instance_selectors := []YamlStrDict{}
	for _, selector := range append(PRESET_CHAINS, c.Selector...) {
		var _p []string

		if selector == "PROXY" {
			_p = append(instance_groups_keys, "DIRECT")
		} else if selector == "FALLBACK" {
			_p = []string{"PROXY", "DIRECT"}
		} else {
			_p = append([]string{"PROXY"}, instance_groups_keys...)
		}

		instance_selectors = append(instance_selectors, YamlStrDict{
			"name":    selector,
			"type":    "select",
			"proxies": _p,
		})
	}

	instance["proxy-groups"] = append(instance_selectors, instance_groups...)

	if c.NoRuleProviders {
		rule_providers := instance["rule-providers"].(map[interface{}]interface{})
		delete(instance, "rule-providers")

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
		for _, rule := range instance["rules"].([]interface{}) {
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
				if behavior == "domain" {
					new_rule = fmt.Sprintf("DOMAIN,%s,%s", pattern, rule_action)
				} else if behavior == "ipcidr" {
					new_rule = fmt.Sprintf("IP-CIDR,%s,%s", pattern, rule_action)
				} else if behavior == "classical" {
					if strings.Contains(pattern, ",no-resolve") {
						pattern = strings.Replace(pattern, ",no-resolve", "", 1)
						new_rule = fmt.Sprintf("%s,%s,no-resolve", pattern, rule_action)
					} else {
						new_rule = fmt.Sprintf("%s,%s", pattern, rule_action)
					}
				} else {
					continue
				}
				rules = append(rules, new_rule)
			}
		}
		instance["rules"] = rules
	}

	return instance, nil
}
