package main

import "regexp"

var CN *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong|tw|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)`)
var HK *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong)\b|🇭🇰|香港)`)
var TW *regexp.Regexp = regexp.MustCompile(`(?i)(\b(tw|taiwan)\b|台湾)`)
var US *regexp.Regexp = regexp.MustCompile(`(?i)(\b(us|usa|united states|america|los angeles|san jose|silicon valley|seattle|portland|phoenix|dallas|denver|chicago|new york|ashburn)\b|🇺🇸|美国)`)

var organizerClassifiers = []struct {
	name    string
	matcher func(YamlStrDict) bool
}{
	{name: "cn", matcher: isCN},
	{name: "tw", matcher: isTW},
	{name: "us", matcher: isUS},
	{name: "oversea", matcher: isOversea},
	{name: "udp", matcher: isUDP},
}

func proxyName(proxy YamlStrDict) (string, bool) {
	name, ok := proxy["name"].(string)
	return name, ok
}

func isAny(proxy YamlStrDict) bool {
	return true
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

func isUDP(proxy YamlStrDict) bool {
	udp, ok := proxy["udp"].(bool)
	return ok && udp
}
