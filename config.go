package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
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

	proxyRaw, err := asAnyList(obj["proxies"], "proxies")
	if err != nil {
		return nil, fmt.Errorf("proxies not found")
	}
	proxies := NewDictList(proxyRaw)
	groupRaw, err := asAnyList(obj["proxy-groups"], "proxy-groups")
	if err != nil {
		return nil, fmt.Errorf("proxy-groups not found")
	}
	groups := NewDictList(groupRaw)

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
			if err := merged.groupAddProxies(key, group["proxies"]); err != nil {
				log.Printf("Failed to merge proxies for group %s: %v", key, err)
			}
		}
	}

	return merged
}

func resolveAirportNameConflicts(airports map[string]Airport) {
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

	PortProxy   bool
	BindAddress string
	HttpPort    int
	SocksPort   int
	MixedPort   int

	TransProxy bool
	RedirPort  int
	TproxyPort int

	AllowLan                 bool
	ExternalControllerType   ExternalControllerType
	ExternalControllerAddr   string
	ExternalControllerSecret string

	Dns               bool
	DnsListen         string
	EnhancedMode      string
	DefaultNameserver []string
	Nameserver        []string
	Fallback          []string
	NameserverPolicy  map[string]string

	Tun      bool
	TunStack string
	LogLevel string

	RuleProviderTransform RuleProviderTransform
	CustomRules           []string
	Platform              Platform
}

func (c *Config) Validate() error {
	if c.Upstreams == nil {
		return fmt.Errorf("need upstreams")
	}

	return nil
}

func (c *Config) selectedUpstreams() []AirportSpec {
	selected := []AirportSpec{}
	userTags := c.Upstream
	if len(userTags) == 0 {
		userTags = []string{"default"}
	}
	for _, upstream := range c.Upstreams {
		if !upstream.enabled() {
			continue
		}
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

func (c *Config) hasOrganizerGroup(key string) bool {
	for _, group := range c.Organizer {
		if group == key {
			return true
		}
	}
	return false
}

func (c *Config) generate(r *http.Request) (YamlStrDict, error) {
	templateCopy, err := deepCopyTemplate(c.Template)
	if err != nil {
		return nil, err
	}

	cfg := *c
	cfg.Template = templateCopy

	allSelectors := cfg.collectSelectors()

	if err := cfg.applyBaseTemplateOptions(); err != nil {
		return nil, err
	}
	if err := cfg.applyDNSOptions(); err != nil {
		return nil, err
	}
	if err := cfg.applyTunOptions(); err != nil {
		return nil, err
	}

	airports := cfg.fetchAirports()
	resolveAirportNameConflicts(airports)
	allProxies := collectAllProxies(airports)
	cfg.Template["proxies"] = allProxies.values()
	cfg.Template["proxy-groups"] = cfg.buildProxyGroups(airports, allProxies, allSelectors)

	if err := cfg.transformRuleProviders(r); err != nil {
		return nil, err
	}

	return cfg.Template, nil
}

func (c *Config) collectSelectors() []string {
	tplRulesRaw, ok := c.Template["rules"]
	if !ok {
		return []string{"PROXY", "UDP", "FALLBACK", "CNSITE"}
	}
	ruleItems, err := asAnyList(tplRulesRaw, "rules")
	if err != nil {
		return []string{"PROXY", "UDP", "FALLBACK", "CNSITE"}
	}

	presetChains := map[string]struct{}{
		"DIRECT":   {},
		"REJECT":   {},
		"PROXY":    {},
		"UDP":      {},
		"FALLBACK": {},
		"CNSITE":   {},
	}
	customSelectors := []string{}
	for _, ruleItem := range ruleItems {
		rule, ok := ruleItem.(string)
		if !ok {
			continue
		}
		chain, ok := extractRuleTarget(rule)
		if !ok {
			continue
		}
		if _, exists := presetChains[chain]; exists {
			continue
		}
		presetChains[chain] = struct{}{}
		customSelectors = append(customSelectors, chain)
	}

	return append(append([]string{"PROXY"}, customSelectors...), "UDP", "FALLBACK", "CNSITE")
}

func extractRuleTarget(rule string) (string, bool) {
	parts := splitRuleSegments(rule)
	if len(parts) < 2 {
		return "", false
	}

	targetIndex, ok := ruleTargetIndex(parts)
	if !ok || targetIndex >= len(parts) {
		return "", false
	}

	target := strings.TrimSpace(parts[targetIndex])
	if target == "" {
		return "", false
	}
	return target, true
}

func splitRuleSegments(rule string) []string {
	rawParts := strings.Split(rule, ",")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func ruleTargetIndex(parts []string) (int, bool) {
	if len(parts) < 2 {
		return 0, false
	}

	ruleType := strings.ToUpper(parts[0])
	switch ruleType {
	case "MATCH", "FINAL":
		return 1, true
	case "RULE-SET", "RULE-SET-IPCIDR", "GEOSITE", "GEOIP", "IP-ASN", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "IN-TYPE", "IN-PORT", "IN-USER", "IN-NAME", "PROCESS-NAME", "PROCESS-PATH", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "URL-REGEX", "USER-AGENT", "NETWORK", "DSCP":
		if len(parts) >= 3 {
			return 2, true
		}
		return 0, false
	case "AND", "OR":
		if len(parts) >= 2 {
			return len(parts) - 1, true
		}
		return 0, false
	case "NOT":
		if len(parts) >= 3 {
			return len(parts) - 1, true
		}
		return 0, false
	default:
		if len(parts) >= 3 {
			return len(parts) - 1, true
		}
		if len(parts) == 2 {
			return 1, true
		}
		return 0, false
	}
}

func (c *Config) applyBaseTemplateOptions() error {
	log.Printf("Applying base template options: port_proxy=%t trans_proxy=%t external_controller=%s", c.PortProxy, c.TransProxy, c.ExternalControllerType)
	if c.PortProxy {
		c.Template["allow-lan"] = c.AllowLan
		c.Template["bind-address"] = c.BindAddress

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
		switch c.ExternalControllerType {
		case HTTP:
			c.Template["external-controller"] = c.ExternalControllerAddr
		case HTTPS:
			c.Template["external-controller-tls"] = c.ExternalControllerAddr
		case UNIX:
			c.Template["external-controller-unix"] = c.ExternalControllerAddr
		}
	}

	c.Template["secret"] = c.ExternalControllerSecret
	if c.LogLevel != "" {
		c.Template["log-level"] = c.LogLevel
	}
	return nil
}

func (c *Config) applyDNSOptions() error {
	if !c.Dns {
		return nil
	}
	log.Printf("Applying DNS options: listen=%s enhanced_mode=%s nameservers=%d fallback=%d", c.DnsListen, c.EnhancedMode, len(c.Nameserver), len(c.Fallback))

	dns, err := asStringAnyMapField(c.Template, "dns")
	if err != nil {
		return err
	}

	dns["enable"] = true
	dns["listen"] = c.DnsListen
	dns["enhanced-mode"] = c.EnhancedMode
	dns["default-nameserver"] = c.DefaultNameserver
	dns["nameserver"] = c.Nameserver
	dns["fallback"] = c.Fallback
	dns["nameserver-policy"] = c.NameserverPolicy
	c.Template["dns"] = dns
	return nil
}

func (c *Config) applyTunOptions() error {
	if !c.Tun {
		return nil
	}
	log.Printf("Applying TUN options: stack=%s platform=%s", c.TunStack, c.Platform)

	tun, err := asStringAnyMapField(c.Template, "tun")
	if err != nil {
		return err
	}

	tun["enable"] = true
	tun["stack"] = c.TunStack
	if c.Platform == Windows {
		tun["auto-redir"] = false
	}
	c.Template["tun"] = tun
	return nil
}

func (c *Config) fetchAirports() map[string]Airport {
	log.Printf("Fetching airports for upstream selectors: %v", c.Upstream)
	type pair struct {
		k string
		v Airport
	}

	airports := map[string]Airport{}
	selectedUpstreams := c.selectedUpstreams()
	ch := make(chan pair, len(selectedUpstreams))

	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, upstream := range selectedUpstreams {
		upstreamCopy := upstream
		log.Printf("Scheduling upstream fetch: name=%s urls=%d ttl=%d cache_on_err=%t", upstreamCopy.Name, len(upstreamCopy.Urls), upstreamCopy.Ttl, upstreamCopy.UseCacheOnErr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resolvedAirports := []Airport{}
			for idx, rawURL := range upstreamCopy.Urls {
				parsedURL, err := url.Parse(rawURL)
				if err != nil {
					log.Printf("Skipping invalid upstream URL: upstream=%s index=%d err=%v", upstreamCopy.Name, idx, err)
					continue
				}
				airport, err := downloadUpstream(parsedURL, fmt.Sprintf("upstream-%s-%d.yaml", upstreamCopy.Name, idx), upstreamCopy.Ttl, 15, upstreamCopy.UseCacheOnErr)
				if err != nil {
					log.Printf("Failed upstream URL: upstream=%s index=%d err=%v", upstreamCopy.Name, idx, err)
					continue
				}
				resolvedAirports = append(resolvedAirports, *airport)
			}
			mergedAirport := stackAirports(resolvedAirports)
			log.Printf("Finished upstream fetch: name=%s resolved_variants=%d merged_proxies=%d merged_groups=%d", upstreamCopy.Name, len(resolvedAirports), len(mergedAirport.Proxies), len(mergedAirport.Groups))
			ch <- pair{upstreamCopy.Name, mergedAirport}
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for p := range ch {
		airports[p.k] = p.v
	}

	log.Printf("Fetched upstream set: count=%d", len(airports))
	return airports
}

func collectAllProxies(airports map[string]Airport) DictList {
	allProxies := DictList{}
	for _, airport := range airports {
		allProxies.update(airport.Proxies)
	}
	return allProxies
}

func (c *Config) buildProxyGroups(airports map[string]Airport, allProxies DictList, allSelectors []string) []YamlStrDict {
	log.Printf("Building proxy groups: selectors=%d airports=%d proxies=%d", len(allSelectors)+len(c.TopSelect), len(airports), len(allProxies))
	instanceURLTestGroups := []YamlStrDict{}
	groupKey := "all"

	if len(allProxies) > 0 {
		instanceURLTestGroups = append(instanceURLTestGroups, makeURLTestGroup(groupKey, allProxies.keys()))
	}

	instanceURLTestGroups = append(instanceURLTestGroups, c.buildOrganizerGroups(groupKey, allProxies)...)

	for name, airport := range airports {
		airportProxies := airport.Proxies
		if len(airportProxies) > 0 {
			airportProxyKeys := airportProxies.keys()
			sort.Strings(airportProxyKeys)
			instanceURLTestGroups = append(instanceURLTestGroups, makeURLTestGroup(name, airportProxyKeys))
		}
		instanceURLTestGroups = append(instanceURLTestGroups, c.buildOrganizerGroups(name, airportProxies)...)
	}

	instanceGroupKeys := []string{}
	for _, g := range instanceURLTestGroups {
		groupName, err := asString(g["name"], "proxy-group.name")
		if err != nil {
			continue
		}
		instanceGroupKeys = append(instanceGroupKeys, groupName)
	}

	instanceSelectorGroups := []YamlStrDict{}
	for _, selector := range append(allSelectors, c.TopSelect...) {
		instanceSelectorGroups = append(instanceSelectorGroups, YamlStrDict{
			"name":    selector,
			"type":    "select",
			"proxies": selectorProxies(selector, instanceGroupKeys),
		})
	}

	return append(instanceSelectorGroups, instanceURLTestGroups...)
}

func makeURLTestGroup(name string, proxies []string) YamlStrDict {
	return YamlStrDict{
		"name":      name,
		"type":      "url-test",
		"proxies":   proxies,
		"url":       "http://www.gstatic.com/generate_204",
		"interval":  300,
		"tolerance": 100,
	}
}

func (c *Config) buildOrganizerGroups(prefix string, proxies DictList) []YamlStrDict {
	groups := []YamlStrDict{}
	classified := classifyProxies(proxies, organizerClassifiers)

	for _, organizer := range organizerClassifiers {
		matched := classified[organizer.name]
		if !c.hasOrganizerGroup(organizer.name) || len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		groups = append(groups, makeURLTestGroup(fmt.Sprintf("%s-%s", prefix, organizer.name), matched))
	}

	return groups
}

func classifyProxies(proxies DictList, classifiers []struct {
	name    string
	matcher func(YamlStrDict) bool
}) map[string][]string {
	classified := make(map[string][]string, len(classifiers))
	for _, classifier := range classifiers {
		classified[classifier.name] = []string{}
	}
	for _, proxy := range proxies {
		name, err := asString(proxy["name"], "proxy.name")
		if err != nil {
			continue
		}
		for _, classifier := range classifiers {
			if classifier.matcher(proxy) {
				classified[classifier.name] = append(classified[classifier.name], name)
			}
		}
	}
	return classified
}

func selectorProxies(selector string, groupKeys []string) []string {
	switch selector {
	case "PROXY":
		return append(groupKeys, "DIRECT")
	case "FALLBACK":
		return []string{"PROXY", "DIRECT"}
	case "CNSITE":
		return []string{"DIRECT", "PROXY"}
	case "UDP":
		return []string{"PROXY", "DIRECT"}
	default:
		proxies := append([]string{"PROXY"}, groupKeys...)
		return append(proxies, "DIRECT")
	}
}

func (c *Config) transformRuleProviders(r *http.Request) error {
	log.Printf("Transforming rule providers with mode=%s", c.RuleProviderTransform)
	if c.RuleProviderTransform == RPT_INLINE {
		return c.inlineRuleProviders()
	}
	if c.RuleProviderTransform == RPT_PROXY {
		return c.proxyRuleProviders(r)
	}
	return nil
}

func (c *Config) inlineRuleProviders() error {
	ruleProviders, err := asStringAnyMapField(c.Template, "rule-providers")
	if err != nil {
		return err
	}
	delete(c.Template, "rule-providers")

	ruleProviderMap := map[string]YamlStrDict{}
	for ruleSetName, ruleProviderRaw := range ruleProviders {
		ruleProvider, err := asStringAnyMap(ruleProviderRaw, fmt.Sprintf("rule-providers.%s", ruleSetName))
		if err != nil {
			return err
		}

		behavior, err := asString(ruleProvider["behavior"], fmt.Sprintf("rule-providers.%s.behavior", ruleSetName))
		if err != nil {
			return err
		}
		ruleProviderURL, err := asString(ruleProvider["url"], fmt.Sprintf("rule-providers.%s.url", ruleSetName))
		if err != nil {
			return err
		}
		url, err := url.Parse(ruleProviderURL)
		if err != nil {
			log.Printf("Failed to parse rule provider url: %v", err)
			return err
		}

		content, err := download(url, fmt.Sprintf("rule-%s.yaml", ruleSetName), 24*time.Hour, 10, true)
		if err != nil {
			log.Printf("Failed to retrieve rule provider: %v", err)
			return err
		}

		if err := yaml.Unmarshal(content, &ruleProvider); err != nil {
			log.Printf("Failed to parse rule provider: %v", err)
			return err
		}

		ruleProviderMap[ruleSetName] = YamlStrDict{
			"name":     ruleSetName,
			"behavior": behavior,
			"patterns": ruleProvider["payload"],
		}
	}

	rules := []string{}
	rulesRaw, ok := c.Template["rules"]
	if !ok {
		return fmt.Errorf("rules config not found in template")
	}
	rulesList, err := asAnyList(rulesRaw, "rules")
	if err != nil {
		return err
	}
	for _, ruleItem := range rulesList {
		rule, ok := ruleItem.(string)
		if !ok {
			continue
		}
		rule_segs := strings.Split(rule, ",")

		if len(rule_segs) < 2 {
			continue
		}
		if rule_segs[0] != "RULE-SET" {
			rules = append(rules, rule)
			continue
		}

		ruleSetName := rule_segs[1]
		ruleProvider, ok := ruleProviderMap[ruleSetName]
		if !ok {
			continue
		}

		rule_action := rule_segs[2]
		behavior, err := asString(ruleProvider["behavior"], fmt.Sprintf("rule-providers.%s.behavior", ruleSetName))
		if err != nil {
			return err
		}
		patterns, err := asStringList(ruleProvider["patterns"], fmt.Sprintf("rule-providers.%s.patterns", ruleSetName))
		if err != nil {
			return err
		}

		expandedRules, err := expandRuleSetPatterns(behavior, patterns, rule_action)
		if err != nil {
			return err
		}
		rules = append(rules, expandedRules...)
	}
	c.Template["rules"] = rules
	return nil
}

func expandRuleSetPatterns(behavior string, patterns []string, ruleAction string) ([]string, error) {
	rules := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		newRule := ""
		switch {
		case strings.HasPrefix(pattern, "DOMAIN"), strings.HasPrefix(pattern, "IP-CIDR"), behavior == "classical":
			if strings.Contains(pattern, ",no-resolve") {
				pattern = strings.Replace(pattern, ",no-resolve", "", 1)
				newRule = fmt.Sprintf("%s,%s,no-resolve", pattern, ruleAction)
			} else {
				newRule = fmt.Sprintf("%s,%s", pattern, ruleAction)
			}
		case behavior == "domain":
			newRule = fmt.Sprintf("DOMAIN,%s,%s", pattern, ruleAction)
		case behavior == "ipcidr":
			newRule = fmt.Sprintf("IP-CIDR,%s,%s", pattern, ruleAction)
		default:
			return nil, fmt.Errorf("unknown rule provider behavior: %s", behavior)
		}
		rules = append(rules, newRule)
	}
	return rules, nil
}

func (c *Config) proxyRuleProviders(r *http.Request) error {
	ruleProviders, err := asStringAnyMapField(c.Template, "rule-providers")
	if err != nil {
		return err
	}
	for ruleSetName, ruleProviderRaw := range ruleProviders {
		ruleProvider, err := asStringAnyMap(ruleProviderRaw, fmt.Sprintf("rule-providers.%s", ruleSetName))
		if err != nil {
			return err
		}

		proxyURL := fmt.Sprintf("%s://%s/rule-providers?rule-set=%s", Scheme(r), HostAndPort(r), ruleSetName)
		ruleProvider["url"] = proxyURL
		ruleProviders[ruleSetName] = ruleProvider
	}
	c.Template["rule-providers"] = ruleProviders
	return nil
}

func deepCopyTemplate(src map[string]any) (YamlStrDict, error) {
	if src == nil {
		return YamlStrDict{}, nil
	}

	data, err := yaml.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template: %w", err)
	}

	var dst YamlStrDict
	if err := yaml.Unmarshal(data, &dst); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template copy: %w", err)
	}
	return dst, nil
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
