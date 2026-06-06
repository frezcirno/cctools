package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleConfigNoQueryServesHTML(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml", nil)
	w := httptest.NewRecorder()

	handleConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := strings.ToLower(w.Body.String())
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!doctype") {
		t.Fatalf("expected index.html HTML content, got %d bytes without an HTML marker", len(body))
	}
}

func TestHandleConfigInvalidBoolParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml?port_proxy=invalid", nil)
	w := httptest.NewRecorder()

	handleConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleConfigInvalidNumberParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/clash/config.yaml?port=abc", nil)
	w := httptest.NewRecorder()

	handleConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleFileOpForbiddenWithWrongToken(t *testing.T) {
	oldToken := token
	token = "secret-token"
	defer func() { token = oldToken }()

	req := httptest.NewRequest("GET", "/upstreams.yaml?token=wrong", nil)
	w := httptest.NewRecorder()

	handleFileOp(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// TestHandleFileOpDeniesWhenTokenUnset guards the empty-TOKEN fail-open bug:
// with no TOKEN configured, file operations must be denied, not granted.
func TestHandleFileOpDeniesWhenTokenUnset(t *testing.T) {
	oldToken := token
	token = ""
	defer func() { token = oldToken }()

	for _, target := range []string{
		"/upstreams.yaml",            // no credentials at all
		"/upstreams.yaml?token=",     // explicit empty token
		"/template.yaml?token=guess", // any token, since none is configured
	} {
		req := httptest.NewRequest("GET", target, nil)
		w := httptest.NewRecorder()
		handleFileOp(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("GET %s with TOKEN unset: status = %d, want 403", target, w.Code)
		}
	}
}

// TestHandleFileOpAcceptsCorrectToken checks each accepted credential channel
// gets past auth (status is not 403) when the token matches.
func TestHandleFileOpAcceptsCorrectToken(t *testing.T) {
	oldToken := token
	token = "secret-token"
	defer func() { token = oldToken }()

	mk := func(setup func(*http.Request)) int {
		req := httptest.NewRequest("GET", "/upstreams.yaml", nil)
		setup(req)
		w := httptest.NewRecorder()
		handleFileOp(w, req)
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

	handleRuleProviders(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleRuleProvidersRejectsPost(t *testing.T) {
	req := httptest.NewRequest("POST", "/rule-providers?rule-set=test", nil)
	w := httptest.NewRecorder()

	handleRuleProviders(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}
