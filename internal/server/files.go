package server

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/frezcirno/cctools/internal/clash"
	"github.com/frezcirno/cctools/internal/vfs"
)

const (
	upstreamsPath = "./upstreams.yaml"
	templatePath  = "./template.yaml"
	indexPath     = "./index.html"
)

// indexHTML is the front-end form, compiled into the binary so the server runs
// from any working directory. An index.html next to the binary overrides it,
// which keeps the edit-and-reload workflow available without a rebuild.
//
//go:embed index.html
var indexHTML []byte

func serveIndex(w http.ResponseWriter, r *http.Request) {
	// Always revalidate so UI changes are never masked by a stale cached copy.
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func loadUpstreams() (map[string]clash.AirportSpec, error) {
	raw, err := vfs.Load(upstreamsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstreams.yaml: %w", err)
	}
	var specs map[string]clash.AirportSpec
	if err := yaml.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("failed to parse upstreams.yaml: %w", err)
	}
	return specs, nil
}

// loadTemplate returns the base config. clash.DefaultTemplate is the source of
// truth; a template.yaml on disk — e.g. uploaded via the token-gated endpoint —
// overrides it when present, for ad-hoc tweaks.
func loadTemplate() (map[string]any, error) {
	if _, err := vfs.Stat(templatePath); err != nil {
		return clash.DefaultTemplate(), nil
	}
	raw, err := vfs.Load(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load template.yaml: %w", err)
	}
	var tpl map[string]any
	if err := yaml.Unmarshal(raw, &tpl); err != nil {
		return nil, fmt.Errorf("failed to parse template.yaml: %w", err)
	}
	return tpl, nil
}

// handleUpstreamList returns the selectable upstreams (enabled only) as JSON so
// the front-end form can render one checkbox per upstream. Only names and the
// "default" flag are exposed — never the upstream URLs (which embed tokens).
func (s *Server) handleUpstreamList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	upstreams, err := loadUpstreams()
	if err != nil {
		log.Printf("Failed to load upstreams for list: %v\n", err)
		http.Error(w, "failed to load upstreams", http.StatusInternalServerError)
		return
	}

	type upstreamOption struct {
		Label   string `json:"label"`   // human-readable name shown in the form
		Value   string `json:"value"`   // tag sent as ?upstream=<value>
		Default bool   `json:"default"` // part of the implicit "default" selection
	}

	keys := make([]string, 0, len(upstreams))
	for k := range upstreams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	options := make([]upstreamOption, 0, len(keys))
	for _, key := range keys {
		spec := upstreams[key]
		if !spec.Enabled() {
			continue
		}
		// The value must be a tag that clash.Config matches on: prefer the
		// name, then an explicit tag, then the map key.
		value := spec.Name
		if value == "" {
			if len(spec.Tags) > 0 {
				value = spec.Tags[0]
			} else {
				value = key
			}
		}
		label := spec.Name
		if label == "" {
			label = key
		}
		isDefault := false
		for _, t := range spec.AllTags() {
			if t == "default" {
				isDefault = true
				break
			}
		}
		options = append(options, upstreamOption{Label: label, Value: value, Default: isDefault})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(options); err != nil {
		log.Printf("Failed to encode upstream list: %v\n", err)
	}
}

// handleFileOp serves token-gated reads and writes of upstreams.yaml and
// template.yaml.
func (s *Server) handleFileOp(w http.ResponseWriter, r *http.Request) {
	// Fail closed: if no token is configured, the read/write endpoints are
	// disabled entirely rather than open to everyone (an empty token must never
	// authenticate an empty credential).
	if s.token == "" {
		http.Error(w, "file operations are disabled: TOKEN is not configured", http.StatusForbidden)
		return
	}

	if subtle.ConstantTimeCompare([]byte(requestToken(r)), []byte(s.token)) != 1 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	path := r.URL.Path[1:]
	if r.Method == http.MethodGet {
		content, err := vfs.Load(path)
		if err != nil {
			// No on-disk override: for template.yaml, fall back to the built-in
			// default (clash.DefaultTemplate) so callers can still inspect or
			// download the effective base config instead of getting a 404.
			if path == "template.yaml" {
				if out, mErr := yaml.Marshal(clash.DefaultTemplate()); mErr == nil {
					w.Header().Set("Content-Type", "application/x-yaml")
					w.Write(out)
					return
				}
			}
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Write(content)
		return
	}

	// 上传文件
	formfile, _, err := r.FormFile("file")
	if err != nil {
		log.Printf("Failed to upload file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer formfile.Close()

	// Use io.ReadAll for robust multipart file reading
	data, err := io.ReadAll(formfile)
	if err != nil {
		log.Printf("Failed to read file: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	vfs.Store(path, data)
}

// requestToken extracts the credential from any of the accepted channels:
// ?token=, "Authorization: Bearer …", or X-Auth-Token.
func requestToken(r *http.Request) string {
	if t := r.URL.Query().Get("token"); t != "" {
		return t
	}
	if t := r.Header.Get("Authorization"); t != "" {
		return strings.TrimPrefix(t, "Bearer ")
	}
	return r.Header.Get("X-Auth-Token")
}
