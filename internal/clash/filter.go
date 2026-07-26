package clash

import "regexp"

var CN *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong|tw|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)`)
var HK *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong)\b|🇭🇰|香港)`)
var TW *regexp.Regexp = regexp.MustCompile(`(?i)(\b(tw|taiwan)\b|台湾)`)
var US *regexp.Regexp = regexp.MustCompile(`(?i)(\b(us|usa|united states|america|los angeles|san jose|silicon valley|seattle|portland|phoenix|dallas|denver|chicago|new york|ashburn)\b|🇺🇸|美国)`)
var SG *regexp.Regexp = regexp.MustCompile(`(?i)(\b(sg|singapore)\b|🇸🇬|新加坡|狮城|獅城)`)
var JP *regexp.Regexp = regexp.MustCompile(`(?i)(\b(jp|japan|tokyo|osaka)\b|🇯🇵|日本|东京|大阪|東京)`)

type NodeClassifier struct {
	name    string
	matcher func(YamlStrDict) bool
}

var NodeClassifiers = []NodeClassifier{
	{name: "cn", matcher: isCN},
	{name: "tw", matcher: isTW},
	{name: "us", matcher: isUS},
	{name: "sg", matcher: isSG},
	{name: "jp", matcher: isJP},
	{name: "oversea", matcher: isOversea},
	{name: "udp", matcher: isUDP},
}

func ClassifyNodes(proxies DictList, classifiers []NodeClassifier) map[string][]string {
	classified := make(map[string][]string, len(classifiers))
	for _, classifier := range classifiers {
		classified[classifier.name] = []string{}
	}
	proxies.ForEach(func(_ string, proxy YamlStrDict) {
		name, err := asString(proxy["name"], "proxy.name")
		if err != nil {
			return
		}
		for _, classifier := range classifiers {
			if classifier.matcher(proxy) {
				classified[classifier.name] = append(classified[classifier.name], name)
			}
		}
	})
	return classified
}

func proxyName(proxy YamlStrDict) (string, bool) {
	name, ok := proxy["name"].(string)
	return name, ok
}

func isCN(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && CN.MatchString(name)
}

func isOversea(proxy YamlStrDict) bool {
	return !isCN(proxy)
}

func isTW(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && TW.MatchString(name)
}

func isHK(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && HK.MatchString(name)
}

func isUS(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && US.MatchString(name)
}

func isSG(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && SG.MatchString(name)
}

func isJP(proxy YamlStrDict) bool {
	name, ok := proxyName(proxy)
	return ok && JP.MatchString(name)
}

func isUDP(proxy YamlStrDict) bool {
	udp, ok := proxy["udp"].(bool)
	return ok && udp
}
