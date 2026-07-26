// Package server exposes the HTTP surface: the config generator, the
// token-gated config file endpoints, and the rule-provider proxies.
package server

import (
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
	"time"

	"github.com/frezcirno/cctools/internal/clash"
	"github.com/frezcirno/cctools/internal/vfs"
)

// Server holds the per-deployment configuration shared by all handlers.
type Server struct {
	// token gates the /upstreams.yaml and /template.yaml endpoints. When empty
	// those endpoints are disabled entirely (fail closed) rather than open.
	token string
}

// New builds a Server and preloads ./upstreams.yaml into the vfs.
//
// Only upstreams.yaml is preloaded from disk. template.yaml is not required:
// the base config is built in Go (clash.DefaultTemplate); an on-disk
// template.yaml is an optional override loaded lazily.
func New(token string) *Server {
	src, err := vfs.Load(upstreamsPath)
	if err != nil {
		// Don't fail on boot: the file may be supplied later via the
		// token-gated upload endpoint, and on a read-only/serverless FS it may
		// live elsewhere. Requests surface a clear error until it exists.
		log.Printf("Warning: %s not loaded at startup: %v", upstreamsPath, err)
	} else {
		vfs.Store(upstreamsPath, src)
	}
	return &Server{token: token}
}

// Handler returns the fully routed HTTP handler, panic-recovery included.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/clash/config.yaml", s.handleConfig)
	mux.HandleFunc("/upstreams.yaml", s.handleFileOp)
	mux.HandleFunc("/template.yaml", s.handleFileOp)
	mux.HandleFunc("/upstreams-list", s.handleUpstreamList)
	mux.HandleFunc("/rule-providers", s.handleRuleProviders)
	mux.Handle("/convert", s.makeConvertProxy())
	return recoverMiddleware(mux)
}

// recoverMiddleware turns any panic that escapes a handler into a 500 instead
// of a dropped connection, so a single bad request can never take the server
// down. (Panics in handler-spawned goroutines must still be recovered at their
// own goroutine boundary — see clash.Config.fetchAirports.)
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Recovered from panic handling %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// sensitiveFields are scrubbed from request dumps before logging. They are
// covered as both query params (field=value) and header values (Field: value):
// "url" hides the /convert subscription URL (which embeds tokens),
// "authorization"/"x-auth-token" hide the file-op credentials.
var sensitiveFields = []string{"token", "secret", "external_controller_addr", "nameserver_policy", "url", "authorization", "x-auth-token"}

func logRequest(r *http.Request) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Failed to dump request: %v\n", err)
		return
	}
	dumpStr := string(requestDump)
	for _, field := range sensitiveFields {
		// Sanitize query parameters
		re := regexp.MustCompile(`(?i)` + field + `=([^&\s]+)`)
		dumpStr = re.ReplaceAllString(dumpStr, field+"=[REDACTED]")
		// Sanitize header values
		re = regexp.MustCompile(`(?i)(` + field + `:\s*)([^\r\n]+)`)
		dumpStr = re.ReplaceAllString(dumpStr, "${1}[REDACTED]")
	}
	log.Printf("%s Request: %s\n", time.Now().Format("2006-01-02 15:04:05"), dumpStr)
}

// baseURL is how the generated config should address this server, honouring the
// usual reverse-proxy headers.
func baseURL(r *http.Request) clash.BaseURL {
	return clash.BaseURL{Scheme: scheme(r), Host: hostAndPort(r)}
}

func scheme(r *http.Request) string {
	// Can't use `r.Request.URL.Scheme`
	// See: https://groups.google.com/forum/#!topic/golang-nuts/pMUkBlQBDF0
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-Protocol"); v != "" {
		return v
	}
	if ssl := r.Header.Get("X-Forwarded-Ssl"); ssl == "on" {
		return "https"
	}
	if v := r.Header.Get("X-Url-Scheme"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Scheme"); v != "" {
		return v
	}
	return "http"
}

func hostAndPort(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = r.Header.Get("Host")
	}
	return host
}
