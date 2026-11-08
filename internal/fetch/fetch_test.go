package fetch

import (
	"strings"
	"testing"
)

func TestBodySnippet(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", " \n\t ", ""},
		{"provider message", "Secure Token Expired or Not Authorized, Please Reauthorize at Control Panel\n",
			` (body: "Secure Token Expired or Not Authorized, Please Reauthorize at Control Panel")`},
		{"collapses lines and drops control chars", "a\r\n\x1b[31mb\x00c", ` (body: "a [31mbc")`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodySnippet([]byte(tc.body)); got != tc.want {
				t.Fatalf("bodySnippet() = %q, want %q", got, tc.want)
			}
		})
	}

	long := bodySnippet([]byte(strings.Repeat("x", 1000)))
	if !strings.HasSuffix(long, `…")`) || len([]rune(long)) > 220 {
		t.Fatalf("long body not truncated: %d runes", len([]rune(long)))
	}
}
