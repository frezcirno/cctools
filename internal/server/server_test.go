package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/frezcirno/cctools/internal/ruleset"
)

func TestHandleConfigNoQueryServesHTML(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := strings.ToLower(w.Body.String())
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!doctype") {
		t.Fatalf("expected index.html HTML content, got %d bytes without an HTML marker", len(body))
	}
}

func TestConfigPageUsesValidDOMQueryMethods(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleConfig(w, req)

	body := w.Body.String()
	for _, invalid := range []string{"document.querySelect(", "document.querySelectAll("} {
		if strings.Contains(body, invalid) {
			t.Errorf("configuration page contains invalid DOM method %q", invalid)
		}
	}
}

func TestHandleConfigInvalidBoolParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml?port_proxy=invalid", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleConfigInvalidNumberParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml?port=abc", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleFileOpForbiddenWithWrongToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/upstreams.yaml?token=wrong", nil)
	w := httptest.NewRecorder()

	(&Server{token: "secret-token"}).handleFileOp(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// TestHandleFileOpDeniesWhenTokenUnset guards the empty-token fail-open bug:
// with no token configured, file operations must be denied, not granted.
func TestHandleFileOpDeniesWhenTokenUnset(t *testing.T) {
	s := &Server{token: ""}

	for _, target := range []string{
		"/upstreams.yaml",            // no credentials at all
		"/upstreams.yaml?token=",     // explicit empty token
		"/template.yaml?token=guess", // any token, since none is configured
	} {
		req := httptest.NewRequest("GET", target, nil)
		w := httptest.NewRecorder()
		s.handleFileOp(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("GET %s with token unset: status = %d, want 403", target, w.Code)
		}
	}
}

// TestHandleFileOpAcceptsCorrectToken checks each accepted credential channel
// gets past auth (status is not 403) when the token matches.
func TestHandleFileOpAcceptsCorrectToken(t *testing.T) {
	s := &Server{token: "secret-token"}

	mk := func(setup func(*http.Request)) int {
		req := httptest.NewRequest("GET", "/upstreams.yaml", nil)
		setup(req)
		w := httptest.NewRecorder()
		s.handleFileOp(w, req)
		return w.Code
	}

	channels := map[string]func(*http.Request){
		"query":        func(r *http.Request) { r.URL.RawQuery = "token=secret-token" },
		"bearer":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer secret-token") },
		"x-auth-token": func(r *http.Request) { r.Header.Set("X-Auth-Token", "secret-token") },
	}
	for name, setup := range channels {
		if code := mk(setup); code == http.StatusForbidden {
			t.Errorf("channel %s: got 403 with correct token, want auth to pass", name)
		}
	}
}

func TestHandleRuleProvidersRequiresRuleSet(t *testing.T) {
	req := httptest.NewRequest("GET", "/rule-providers", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleRuleProviders(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleRuleProvidersRejectsPost(t *testing.T) {
	req := httptest.NewRequest("POST", "/rule-providers?rule-set=test", nil)
	w := httptest.NewRecorder()

	(&Server{}).handleRuleProviders(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestConvertRawListToRuleProvider(t *testing.T) {
	withRules, has := ruleset.ConvertRawList([]byte("DOMAIN,example.com\n# a comment\nIP-CIDR,1.1.1.0/24\n"))
	if !has {
		t.Fatal("expected hasRules=true")
	}
	if !bytes.Contains(withRules, []byte("payload:")) || !bytes.Contains(withRules, []byte(" - DOMAIN,example.com")) {
		t.Fatalf("expected payload + rule lines, got:\n%s", withRules)
	}

	// Comment-only and empty inputs must still produce a valid payload mapping.
	for _, in := range []string{"# only a comment\n\n", ""} {
		out, has := ruleset.ConvertRawList([]byte(in))
		if has {
			t.Errorf("input %q: expected hasRules=false", in)
		}
		if !bytes.Contains(out, []byte("payload: []")) {
			t.Errorf("input %q: expected 'payload: []', got:\n%s", in, out)
		}
		if bytes.Contains(out, []byte("\n - ")) {
			t.Errorf("input %q: unexpected rule line in degenerate output:\n%s", in, out)
		}
	}
}

func TestDetectPlatformFromUserAgent(t *testing.T) {
	cases := map[string]string{
		"clash-verge/v1.5.0 (Windows NT 10.0)": "windows",
		"mihomo/1.18.0 (Linux x86_64)":         "linux",
		"Clash/1.0 (Android 14)":               "android",
		"ClashX/1.95.1 Darwin":                 "darwin",
		"curl/8.4.0":                           "other",
		// Windows is checked first: a UA naming both still resolves to windows.
		"ClashforWindows/0.20.39 Linux": "windows",
	}
	for ua, want := range cases {
		if got := string(detectPlatform(ua)); got != want {
			t.Errorf("detectPlatform(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestBaseURLHonorsForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "http://internal:9000/clash/config.yaml", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "sub.example.com")

	if got := baseURL(req).String(); got != "https://sub.example.com" {
		t.Fatalf("baseURL() = %q, want https://sub.example.com", got)
	}
}
