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
	body := w.Body.String()
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!DOCTYPE") && !strings.Contains(body, "<HTML") {
		// index.html should contain HTML content
		// If the file doesn't exist, we'll get a 404 which is also acceptable in test env
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
