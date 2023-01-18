package main

import "regexp"

var CN *regexp.Regexp = regexp.MustCompile(`(?i)(\b(hk|hong ?kong|tw|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)`)

var TW *regexp.Regexp = regexp.MustCompile(`(?i)(\b(tw|taiwan)\b|台湾)`)

func isAny(proxy YamlStrDict) bool {
	return true
}

func isCN(proxy YamlStrDict) bool {
	return CN.MatchString(proxy["name"].(string))
}

func isOversea(proxy YamlStrDict) bool {
	return !CN.MatchString(proxy["name"].(string))
}

func isTW(proxy YamlStrDict) bool {
	return TW.MatchString(proxy["name"].(string))
}

func isHK(proxy YamlStrDict) bool {
	return CN.MatchString(proxy["name"].(string))
}

func isUDP(proxy YamlStrDict) bool {
	if udp, ok := proxy["udp"]; ok {
		return udp.(bool)
	} else {
		return false
	}
}
