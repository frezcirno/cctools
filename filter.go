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

func isAny(proxy YamlStrDict) bool {
	return true
}

func isCN(proxy YamlStrDict) bool {
	return CN.MatchString(proxy["name"].(string))
}

func isOversea(proxy YamlStrDict) bool {
	return !isCN(proxy)
}

func isTW(proxy YamlStrDict) bool {
	return TW.MatchString(proxy["name"].(string))
}

func isHK(proxy YamlStrDict) bool {
	return HK.MatchString(proxy["name"].(string))
}

func isUS(proxy YamlStrDict) bool {
	return US.MatchString(proxy["name"].(string))
}

func isUDP(proxy YamlStrDict) bool {
	if udp, ok := proxy["udp"]; ok {
		return udp.(bool)
	} else {
		return false
	}
}
