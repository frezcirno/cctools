package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

var PROXY_BLACKLIST = []string{"DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"}

func randomStr(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func downloadUpstream(upstream *url.URL, upstream_name string, ttl_sec int, timeout int, use_cache_on_err bool) (*Airport, error) {
	ttl := time.Duration(ttl_sec) * time.Second
	cache_key := make_cache_key(upstream)
	content, err := download(upstream, upstream_name, ttl, timeout, use_cache_on_err)
	if err != nil {
		log.Printf("Failed to download upstream %v: %v", upstream, err)
		return nil, err
	}

	airport, err := parseUpstream(content)
	if err != nil {
		log.Printf("Failed to parse downloaded upstream %v: %v", upstream, err)

		cache_ok, _ := cache_is_ok(cache_key, ttl)
		if use_cache_on_err && cache_ok {
			log.Printf("Retry cached upstream for %v", upstream)
			content, err := load_cache(cache_key)
			if err == nil {
				return parseUpstream(content)
			}
		}

		return nil, err
	}

	save_cache(cache_key, content)
	return airport, nil
}

func parseUpstream(content []byte) (*Airport, error) {
	var obj YamlStrDict
	if err := yaml.Unmarshal(content, &obj); err != nil {
		return nil, err
	}

	_proxies, ok := obj["proxies"].([]any)
	if !ok {
		err := fmt.Errorf("proxies not found")
		return nil, err
	}
	proxies := NewDictList(_proxies)
	_groups, ok := obj["proxy-groups"].([]any)
	if !ok {
		err := fmt.Errorf("proxy-groups not found")
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
			merged.groupAddProxies(key, group["proxies"].([]any))
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

type Config struct {
	Template  map[string]any
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
		for _, rule := range tpl_rules.([]any) {
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
		dns := c.Template["dns"].(map[any]any)
		dns["enable"] = true
		dns["listen"] = c.DnsListen
		dns["enhanced-mode"] = c.EnhancedMode

		dns["default-nameserver"] = c.DefaultNameserver
		dns["nameserver"] = c.Nameserver
		dns["fallback"] = c.Fallback
		dns["nameserver-policy"] = c.NameserverPolicy // .(map[any]any)["+.zju.edu.cn"] = dhcpdns
	}

	if c.Tun {
		tun := c.Template["tun"].(map[any]any)
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
				airport, err := downloadUpstream(u, fmt.Sprintf("upstream-%s-%d.yaml", _copy.Name, idx), _copy.Ttl, 15, _copy.UseCacheOnErr)
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
			"interval":  300,
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
			"interval":  300,
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
			"interval":  300,
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
			"interval":  300,
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
			"interval":  300,
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
				"interval":  300,
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
				"interval":  300,
				"tolerance": 100,
			})
		}

		if c.contains_group("tw") && len(_tw) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-tw", name),
				"type":      "url-test",
				"proxies":   _tw,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}

		if c.contains_group("oversea") && len(_oversea) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-oversea", name),
				"type":      "url-test",
				"proxies":   _oversea,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 100,
			})
		}

		if c.contains_group("udp") && len(_udp) > 0 {
			instance_urltest_groups = append(instance_urltest_groups, YamlStrDict{
				"name":      fmt.Sprintf("%s-udp", name),
				"type":      "url-test",
				"proxies":   _udp,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
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
		rule_providers := c.Template["rule-providers"].(map[any]any)
		delete(c.Template, "rule-providers")

		rule_provider_map := map[string]YamlStrDict{}
		for rule_set_name, rule_provider := range rule_providers {
			rule_set_name := rule_set_name.(string)
			rule_provider := rule_provider.(map[any]any)

			behavior := rule_provider["behavior"].(string)
			url, err := url.Parse(rule_provider["url"].(string))
			if err != nil {
				log.Printf("Failed to parse rule provider url: %v", err)
				return nil, err
			}

			content, err := download(url, fmt.Sprintf("rule-%s.yaml", rule_set_name), 24*time.Hour, 10, true)
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
		for _, rule := range c.Template["rules"].([]any) {
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

			for _, pattern := range rule_provider["patterns"].([]any) {
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
		rule_providers := c.Template["rule-providers"].(map[any]any)
		for rule_set_name, rule_provider := range rule_providers {
			rule_set_name := rule_set_name.(string)
			rule_provider := rule_provider.(map[any]any)

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
