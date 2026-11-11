// Package intunemock is a test double for the Microsoft services the bridge
// calls: Entra ID (OIDC metadata and client-credentials tokens), Graph service
// discovery, and the Intune ScepActions API. It exists so the bridge can be
// developed and tested end to end without a Microsoft tenant. Never point a
// production bridge at it.
//
// Outcomes are chosen by the SCEP challenge carried in the CSR:
// "reject-..." is a definitive rejection, "error-..." a transient upstream
// failure (HTTP 503), a CSR without a challenge is rejected, anything else is
// accepted. Every validation and notification is recorded and exposed at
// /_mock/requests.
package intunemock

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	defaultAppID       = "0000000a-0000-0000-c000-000000000000"
	defaultIntuneScope = "https://api.manage.microsoft.com/.default"
	providerName       = "ScepRequestValidationFEService"
	tokenPrefix        = "mock."

	// maxBodyBytes caps request bodies; real requests are a few KiB.
	maxBodyBytes = 1 << 20
	// defaultMaxRecords bounds the request log; the oldest entries are dropped.
	defaultMaxRecords = 1000
)

// Options configure the mock. BaseURL is required: it's the address clients
// use to reach the mock, used in metadata and discovery responses.
type Options struct {
	BaseURL      string // e.g. https://intune-mock:8443 (no trailing slash needed)
	GraphScope   string // default BaseURL + "/.default"
	IntuneScope  string // default https://api.manage.microsoft.com/.default
	AppID        string // default Intune's app ID
	ClientID     string // when set, the only client ID the token endpoint accepts
	ClientSecret string // when set, the only secret the token endpoint accepts
	MaxRecords   int    // request log size; default 1000, oldest dropped first
}

// ValidateBaseURL reports whether s can be the mock's base URL: an absolute
// https URL with a host. The Azure SDK only accepts an https authority, and the
// base URL is what metadata and discovery hand back to clients.
func ValidateBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("intunemock: base URL must be an absolute https URL, e.g. https://intune-mock:8443")
	}
	return nil
}

// Record is one validation or notification the mock received.
type Record struct {
	Kind          string `json:"kind"` // validate, success or failure
	TransactionID string `json:"transactionId"`
	Challenge     string `json:"challenge,omitempty"`
	Thumbprint    string `json:"thumbprint,omitempty"`
}

// Mock is an http.Handler serving the mocked Microsoft endpoints.
type Mock struct {
	opts Options
	mux  *http.ServeMux

	mu      sync.Mutex
	records []Record
}

// New builds the mock, filling unset options with their defaults.
func New(opts Options) *Mock {
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.GraphScope == "" {
		opts.GraphScope = opts.BaseURL + "/.default"
	}
	if opts.IntuneScope == "" {
		opts.IntuneScope = defaultIntuneScope
	}
	if opts.AppID == "" {
		opts.AppID = defaultAppID
	}
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = defaultMaxRecords
	}
	m := &Mock{opts: opts, mux: http.NewServeMux(), records: []Record{}}
	m.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", m.handleMetadata)
	m.mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", m.handleToken)
	m.mux.HandleFunc("GET /v1.0/servicePrincipals/{appID}/endpoints", m.handleDiscovery)
	m.mux.HandleFunc("POST /intune/ScepActions/validateRequest", m.handleValidate)
	m.mux.HandleFunc("POST /intune/ScepActions/successNotification", m.handleNotify("success"))
	m.mux.HandleFunc("POST /intune/ScepActions/failureNotification", m.handleNotify("failure"))
	m.mux.HandleFunc("GET /_mock/requests", m.handleListRecords)
	m.mux.HandleFunc("DELETE /_mock/requests", m.handleResetRecords)
	return m
}

func (m *Mock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	m.mux.ServeHTTP(w, r)
}

// decodeJSON decodes the request body, answering 413 when it exceeds
// maxBodyBytes and 400 when it isn't valid JSON. It reports success.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return false
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	return false
}

// Records returns a copy of everything received so far.
func (m *Mock) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.records)) // never nil: an empty list encodes as []
	copy(out, m.records)
	return out
}

func (m *Mock) record(r Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, r)
	if over := len(m.records) - m.opts.MaxRecords; over > 0 {
		m.records = append(m.records[:0:0], m.records[over:]...)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleMetadata serves the OIDC fields MSAL requires. The issuer shares the
// authority's host, which MSAL checks.
func (m *Mock) handleMetadata(w http.ResponseWriter, r *http.Request) {
	base := m.opts.BaseURL + "/" + r.PathValue("tenant")
	writeJSON(w, http.StatusOK, map[string]string{
		"issuer":                 base + "/v2.0",
		"authorization_endpoint": base + "/oauth2/v2.0/authorize",
		"token_endpoint":         base + "/oauth2/v2.0/token",
	})
}

// handleToken implements the client-credentials grant. Tokens are
// "mock.<scope>"; the bridge never inspects them, the mock checks them.
func (m *Mock) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if id == "" || secret == "" ||
		(m.opts.ClientID != "" && id != m.opts.ClientID) ||
		(m.opts.ClientSecret != "" && secret != m.opts.ClientSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	scope, ok := resourceScope(r.PostForm.Get("scope"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
		return
	}
	// Like Entra (AADSTS500011), refuse a token for a resource the mock doesn't
	// serve, so a wrong graph_url/resource_url fails at sign-in.
	if scope != m.opts.GraphScope && scope != m.opts.IntuneScope {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_resource",
			"error_description": "mock: no resource for scope " + scope + " (expected " + m.opts.GraphScope + " or " + m.opts.IntuneScope + ")",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tokenPrefix + scope,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// resourceScope returns the single resource scope of a token request. MSAL
// adds the OIDC scopes (openid, profile, offline_access) to every request;
// Entra issues the token for the resource alone, and so does the mock.
func resourceScope(param string) (string, bool) {
	var resource []string
	for _, s := range strings.Fields(param) {
		switch s {
		case "openid", "profile", "offline_access":
		default:
			resource = append(resource, s)
		}
	}
	if len(resource) != 1 {
		return "", false
	}
	return resource[0], true
}

// authorized reports whether the request carries a token for scope, and
// answers 401 when it doesn't.
func authorized(w http.ResponseWriter, r *http.Request, scope string) bool {
	if r.Header.Get("Authorization") != "Bearer "+tokenPrefix+scope {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "expected_scope": scope})
		return false
	}
	return true
}

func (m *Mock) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, m.opts.GraphScope) {
		return
	}
	if r.PathValue("appID") != "appId="+m.opts.AppID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Request_ResourceNotFound"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]string{
		{"providerName": providerName, "uri": m.opts.BaseURL + "/intune"},
	}})
}

func (m *Mock) handleValidate(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, m.opts.IntuneScope) {
		return
	}
	var body struct {
		Request struct {
			TransactionID      string `json:"transactionId"`
			CertificateRequest []byte `json:"certificateRequest"`
		} `json:"request"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	challenge, err := challengeFromCSR(body.Request.CertificateRequest)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"code": "CsrParsingError", "errorDescription": err.Error()})
		return
	}
	m.record(Record{Kind: "validate", TransactionID: body.Request.TransactionID, Challenge: challenge})
	switch {
	case challenge == "":
		writeJSON(w, http.StatusOK, map[string]string{"code": "ChallengeDecodingError", "errorDescription": "mock: CSR has no challengePassword"})
	case strings.HasPrefix(challenge, "reject-"):
		writeJSON(w, http.StatusOK, map[string]string{"code": "ChallengeDecryptionError", "errorDescription": "mock: challenge rejected"})
	case strings.HasPrefix(challenge, "error-"):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mock: transient failure"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"code": "Success", "errorDescription": ""})
	}
}

func (m *Mock) handleNotify(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r, m.opts.IntuneScope) {
			return
		}
		var body struct {
			Notification struct {
				TransactionID         string `json:"transactionId"`
				CertificateThumbprint string `json:"certificateThumbprint"`
			} `json:"notification"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		m.record(Record{Kind: kind, TransactionID: body.Notification.TransactionID, Thumbprint: body.Notification.CertificateThumbprint})
		writeJSON(w, http.StatusOK, map[string]string{"code": "Success", "errorDescription": ""})
	}
}

func (m *Mock) handleListRecords(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, m.Records())
}

func (m *Mock) handleResetRecords(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	m.records = []Record{}
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// String describes the effective configuration, for startup logs.
func (m *Mock) String() string {
	return fmt.Sprintf("base_url=%s graph_scope=%s intune_scope=%s app_id=%s client_id=%s max_records=%d",
		m.opts.BaseURL, m.opts.GraphScope, m.opts.IntuneScope, m.opts.AppID, orAny(m.opts.ClientID), m.opts.MaxRecords)
}

func orAny(s string) string {
	if s == "" {
		return "(any)"
	}
	return s
}
