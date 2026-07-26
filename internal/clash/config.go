package clash

import (
	"fmt"
	"log"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/frezcirno/cctools/internal/ruleset"
)

const (
	// ruleProviderTTL is how long a downloaded rule-provider body stays usable
	// from the cache.
	ruleProviderTTL = 24 * time.Hour
	// ruleProviderTimeout bounds a single rule-provider download. The largest
	// lists in the default template are several MB, so 10s was not enough on an
	// ordinary link and surfaced as "context deadline exceeded" → HTTP 500.
	ruleProviderTimeout = 60
	// maxConcurrentRuleProviders mirrors the upstream fetch cap: enough
	// parallelism to stay well inside the server's WriteTimeout, not so much
	// that we hammer the rule-list hosts.
	maxConcurrentRuleProviders = 8
)

// PROXY_BLACKLIST names proxies that upstreams inject for signalling rather
// than routing (expiry notices, ad lines, DIRECT/REJECT stubs); they are
// stripped when an upstream is parsed.
var PROXY_BLACKLIST = []string{"DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"}

// Config is one render request: the base template, the upstream catalogue, and
// every option the caller supplied.
type Config struct {
	Template  map[string]any
	Upstreams map[string]AirportSpec

	Upstream  []string
	Organizer []string
	TopSelect []string

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
	Platform              Platform
}

func validatePort(name string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid %s: %d", name, port)
	}
	return nil
}

// validate rejects option combinations that would produce a broken config.
// Generate runs it before doing any work, so callers never invoke it directly.
func (c *Config) validate() error {
	if c.Upstreams == nil {
		return fmt.Errorf("need upstreams")
	}
	if err := validatePort("port", c.HttpPort); err != nil {
		return err
	}
	if err := validatePort("socks_port", c.SocksPort); err != nil {
		return err
	}
	if err := validatePort("mixed_port", c.MixedPort); err != nil {
		return err
	}
	if err := validatePort("redir_port", c.RedirPort); err != nil {
		return err
	}
	if err := validatePort("tproxy_port", c.TproxyPort); err != nil {
		return err
	}
	if c.EnhancedMode != "" {
		switch c.EnhancedMode {
		case "fake-ip", "redir-host":
		default:
			return fmt.Errorf("invalid enhanced_mode: %s", c.EnhancedMode)
		}
	}
	if c.TunStack != "" {
		switch c.TunStack {
		case "system", "gvisor", "mixed":
		default:
			return fmt.Errorf("invalid tun_stack: %s", c.TunStack)
		}
	}
	if c.LogLevel != "" {
		switch c.LogLevel {
		case "debug", "info", "warning", "error", "silent":
		default:
			return fmt.Errorf("invalid log_level: %s", c.LogLevel)
		}
	}

	// The front-end form is the single source of truth: when a section is
	// enabled it always sends the fields that section needs. A missing field
	// here therefore means a malformed/incomplete request, which we reject
	// (400) rather than silently emitting a broken config.
	if c.PortProxy && c.HttpPort == 0 && c.SocksPort == 0 && c.MixedPort == 0 {
		return fmt.Errorf("port_proxy is enabled but no listening port (port/socks_port/mixed_port) was provided")
	}
	if c.TransProxy && c.RedirPort == 0 && c.TproxyPort == 0 {
		return fmt.Errorf("tproxy is enabled but neither redir_port nor tproxy_port was provided")
	}
	if c.Dns {
		if c.DnsListen == "" {
			return fmt.Errorf("dns is enabled but dns_listen is missing")
		}
		if c.EnhancedMode == "" {
			return fmt.Errorf("dns is enabled but enhanced_mode is missing")
		}
		if len(c.Nameserver) == 0 {
			return fmt.Errorf("dns is enabled but nameserver is missing")
		}
	}
	if c.Tun && c.TunStack == "" {
		return fmt.Errorf("tun is enabled but tun_stack is missing")
	}
	if c.ExternalControllerType != NONE && c.ExternalControllerAddr == "" {
		return fmt.Errorf("external_controller_type=%q requires external_controller_addr", c.ExternalControllerType)
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
		if !upstream.Enabled() {
			continue
		}
		matched := false
		for _, userTag := range userTags {
			for _, upstreamTag := range upstream.AllTags() {
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

// Generate renders the final Clash config. base is how the generated document
// should address this server when rewriting rule-provider URLs.
//
// The options are validated first, so an inconsistent Config fails fast with
// *InvalidConfigError before any upstream is fetched.
func (c *Config) Generate(base BaseURL) (YamlStrDict, error) {
	if err := c.validate(); err != nil {
		return nil, &InvalidConfigError{err}
	}

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
	if allProxies.Len() == 0 {
		// Fail closed: every selector would otherwise collapse to DIRECT and the
		// client would silently install a config that routes all traffic
		// unproxied. Returning an error lets the client keep its last-known-good.
		return nil, &UpstreamUnavailableError{fmt.Errorf("no proxies collected from any configured upstream")}
	}
	cfg.Template["proxies"] = allProxies.Values()
	cfg.Template["proxy-groups"] = cfg.buildProxyGroups(airports, allProxies, allSelectors)

	if err := cfg.transformRuleProviders(base); err != nil {
		return nil, err
	}

	return cfg.Template, nil
}

func (c *Config) collectSelectors() []string {
	tplRulesRaw, ok := c.Template["rules"]
	if !ok {
		return []string{"PROXY", "UDP", "UNKNOWN", "CNSITE"}
	}
	ruleItems, err := asAnyList(tplRulesRaw, "rules")
	if err != nil {
		return []string{"PROXY", "UDP", "UNKNOWN", "CNSITE"}
	}

	presetChains := map[string]struct{}{
		"DIRECT":    {},
		"REJECT":    {},
		"PASS":      {},
		"PASS-RULE": {},
		"PROXY":     {},
		"UDP":       {},
		"UNKNOWN":   {},
		"CNSITE":    {},
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

	return append(append([]string{"PROXY"}, customSelectors...), "UDP", "UNKNOWN", "CNSITE")
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
	// Pass-through, not defaulting: a value is written to the template only when
	// it was actually provided. Defaults live in the front-end form (which now
	// always sends them) or in DefaultTemplate() (template.go) — never
	// hardcoded here.
	if c.PortProxy {
		c.Template["allow-lan"] = c.AllowLan
		if c.BindAddress != "" {
			c.Template["bind-address"] = c.BindAddress
		}

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

	// Only override the template's secret when an external controller is being
	// configured or a secret was explicitly supplied. Otherwise a template that
	// ships a real secret would be silently wiped to "" on every request.
	if c.ExternalControllerType != NONE || c.ExternalControllerSecret != "" {
		c.Template["secret"] = c.ExternalControllerSecret
	}
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

	// Pass-through: only override a field when the caller supplied it, otherwise
	// the template's own value (template.yaml dns block) stands. This keeps the
	// backend from injecting defaults or wiping template values to empty.
	dns["enable"] = true
	if c.DnsListen != "" {
		dns["listen"] = c.DnsListen
	}
	if c.EnhancedMode != "" {
		dns["enhanced-mode"] = c.EnhancedMode
	}
	if len(c.DefaultNameserver) > 0 {
		dns["default-nameserver"] = c.DefaultNameserver
	}
	if len(c.Nameserver) > 0 {
		dns["nameserver"] = c.Nameserver
	}
	if len(c.Fallback) > 0 {
		dns["fallback"] = c.Fallback
	}
	if len(c.NameserverPolicy) > 0 {
		dns["nameserver-policy"] = c.NameserverPolicy
	}
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
	if c.TunStack != "" {
		tun["stack"] = c.TunStack
	}
	if c.Platform == Windows {
		tun["auto-redir"] = false
	}
	c.Template["tun"] = tun
	return nil
}

func (c *Config) fetchAirports() map[string]*Airport {
	log.Printf("Fetching airports for upstream selectors: %v", c.Upstream)
	type pair struct {
		k string
		v *Airport
	}

	airports := map[string]*Airport{}
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
			// Defense-in-depth: a panic in this worker goroutine (e.g. from an
			// unexpected type assertion on untrusted upstream content) is NOT
			// recovered by net/http and would crash the whole process. Contain
			// it here so one bad upstream is logged and skipped.
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("Recovered from panic while fetching upstream %s: %v", upstreamCopy.Name, rec)
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()

			resolvedAirports := []*Airport{}
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
				resolvedAirports = append(resolvedAirports, airport)
			}
			mergedAirport := stackAirports(resolvedAirports)
			log.Printf("Finished upstream fetch: name=%s resolved_variants=%d merged_proxies=%d", upstreamCopy.Name, len(resolvedAirports), mergedAirport.Proxies.Len())
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

func collectAllProxies(airports map[string]*Airport) DictList {
	allProxies := NewEmptyDictList()
	for _, name := range sortedAirportKeys(airports) {
		allProxies.Update(airports[name].Proxies)
	}
	return allProxies
}

func (c *Config) buildProxyGroups(airports map[string]*Airport, allProxies DictList, allSelectors []string) []YamlStrDict {
	log.Printf("Building proxy groups: selectors=%d airports=%d proxies=%d", len(allSelectors)+len(c.TopSelect), len(airports), allProxies.Len())
	instanceURLTestGroups := []YamlStrDict{}
	groupKey := "all"

	if allProxies.Len() > 0 {
		instanceURLTestGroups = append(instanceURLTestGroups, makeURLTestGroup(groupKey, allProxies.Keys()))
	}

	instanceURLTestGroups = append(instanceURLTestGroups, c.buildOrganizerGroups(groupKey, allProxies)...)

	for _, name := range sortedAirportKeys(airports) {
		airportProxies := airports[name].Proxies
		if airportProxies.Len() > 0 {
			airportProxyKeys := airportProxies.Keys()
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

const (
	defaultURLTestURL       = "http://www.gstatic.com/generate_204"
	defaultURLTestInterval  = 300
	defaultURLTestTolerance = 100
)

// healthCheckOverrides give an organizer subgroup a probe that actually
// exercises what the group exists for — a "-claude" group that only pinged
// generate_204 would tell you nothing the plain group doesn't. Matched by
// suffix against the group name, first hit wins, so list specific before broad.
var healthCheckOverrides = []struct {
	suffix   string
	url      string
	interval int
}{
	{"-claude", "https://claude.ai", 1800},
	{"-chatbot", "https://chatgpt.com", 1800},
	{"-tw", "https://ani.gamer.com.tw/", 1800},
}

func makeURLTestGroup(name string, proxies []string) YamlStrDict {
	var url string = defaultURLTestURL
	var interval int = defaultURLTestInterval
	lowered := strings.ToLower(name)
	for _, override := range healthCheckOverrides {
		if strings.HasSuffix(lowered, override.suffix) {
			url = override.url
			interval = override.interval
			break
		}
	}
	return YamlStrDict{
		"name":     name,
		"type":     "url-test",
		"proxies":  proxies,
		"url":      url,
		"interval": interval,
		// 新节点延迟必须比当前节点低 tolerance 以上才会切换,防止在两个延迟相近的节点间反复横跳
		"tolerance": defaultURLTestTolerance,
	}
}

func (c *Config) buildOrganizerGroups(prefix string, proxies DictList) []YamlStrDict {
	groups := []YamlStrDict{}
	classified := OrganizeNodes(proxies, DefaultNodeOrganizers)

	for _, organizer := range DefaultNodeOrganizers {
		matched := classified[organizer.name]
		if !slices.Contains(c.Organizer, organizer.name) || len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		groups = append(groups, makeURLTestGroup(fmt.Sprintf("%s-%s", prefix, organizer.name), matched))
	}

	return groups
}

func selectorProxies(selector string, groupKeys []string) []string {
	switch selector {
	case "PROXY":
		return append(groupKeys, "DIRECT")
	case "UNKNOWN":
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

func (c *Config) transformRuleProviders(base BaseURL) error {
	log.Printf("Transforming rule providers with mode=%s", c.RuleProviderTransform)
	if c.RuleProviderTransform == RPT_INLINE {
		return c.inlineRuleProviders()
	}
	if c.RuleProviderTransform == RPT_PROXY {
		return c.proxyRuleProviders(base)
	}
	return nil
}

func (c *Config) inlineRuleProviders() error {
	ruleProviders, err := asStringAnyMapField(c.Template, "rule-providers")
	if err != nil {
		return err
	}
	delete(c.Template, "rule-providers")

	// Read every provider's declared behavior/url first: this is pure map
	// access, and a malformed template should be rejected before any I/O.
	type providerSpec struct{ behavior, url string }
	specs := make(map[string]providerSpec, len(ruleProviders))
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
		specs[ruleSetName] = providerSpec{behavior, ruleProviderURL}
	}

	// Fetch concurrently. The default template has 21 providers and the largest
	// are multiple MB, so downloading them one at a time routinely outran the
	// server's WriteTimeout. Results land in a map, so the completion order
	// can't affect the generated output.
	type providerResult struct {
		body []byte
		err  error
	}
	results := make(map[string]providerResult, len(specs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRuleProviders)

	for ruleSetName, spec := range specs {
		ruleSetName, spec := ruleSetName, spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Rule-provider URLs come from the template and are fetched at
			// request time: only http/https (no local-file reads), and the
			// relative "/convert?url=…" form is expanded in-process rather than
			// by calling our own endpoint over the network.
			body, err := ruleset.Fetch(spec.url, fmt.Sprintf("rule-%s.yaml", ruleSetName), ruleProviderTTL, ruleProviderTimeout)
			mu.Lock()
			results[ruleSetName] = providerResult{body, err}
			mu.Unlock()
		}()
	}
	wg.Wait()

	ruleProviderMap := map[string]YamlStrDict{}
	for ruleSetName, spec := range specs {
		result := results[ruleSetName]
		if result.err != nil {
			log.Printf("Failed to retrieve rule provider %s: %v", ruleSetName, result.err)
			return result.err
		}

		var document YamlStrDict
		if err := yaml.Unmarshal(result.body, &document); err != nil {
			log.Printf("Failed to parse rule provider %s: %v", ruleSetName, err)
			return err
		}

		ruleProviderMap[ruleSetName] = YamlStrDict{
			"name":     ruleSetName,
			"behavior": spec.behavior,
			"patterns": document["payload"],
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
		// A well-formed RULE-SET rule is "RULE-SET,<name>,<action>". Without the
		// action segment there is nothing to expand to — skip rather than panic
		// on rule_segs[2].
		if len(rule_segs) < 3 {
			log.Printf("Skipping malformed RULE-SET rule (no action): %q", rule)
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

func (c *Config) proxyRuleProviders(base BaseURL) error {
	ruleProviders, err := asStringAnyMapField(c.Template, "rule-providers")
	if err != nil {
		return err
	}
	for ruleSetName, ruleProviderRaw := range ruleProviders {
		ruleProvider, err := asStringAnyMap(ruleProviderRaw, fmt.Sprintf("rule-providers.%s", ruleSetName))
		if err != nil {
			return err
		}

		proxyURL := fmt.Sprintf("%s/rule-providers?rule-set=%s", base, url.QueryEscape(ruleSetName))
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
