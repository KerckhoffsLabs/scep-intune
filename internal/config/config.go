// Package config defines the webhook-bridge configuration and its validation.
package config

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Logging configures where and how the server emits logs.
type Logging struct {
	// Output is "stdout", "stderr", or a file path. A file is opened for
	// append and created if absent.
	Output string `yaml:"output"`
	// Format is "json" (default) or "text".
	Format string `yaml:"format"`
	// Level is "debug", "info" (default), "warn", or "error".
	Level string `yaml:"level"`
}

// TLS configures the optional HTTPS listener.
type TLS struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// Server configures the HTTP(S) listener.
type Server struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
}

// Config is the bridge configuration, loaded from YAML with env overrides.
type Config struct {
	Server Server `yaml:"server"`

	// Webhook holds the secrets used to verify step-ca's signed webhook requests
	// (X-Smallstep-Signature). step-ca generates a distinct secret per webhook,
	// so the SCEPCHALLENGE (/validate) and NOTIFYING (/notify) endpoints each
	// have their own.
	Webhook struct {
		// base64 HMAC-SHA256 keys; prefer env SCEP_VALIDATE_SECRET / SCEP_NOTIFY_SECRET.
		ValidateSecret string `yaml:"validate_secret"`
		NotifySecret   string `yaml:"notify_secret"`
	} `yaml:"webhook"`

	Logging Logging `yaml:"logging"`

	Intune struct {
		TenantID     string `yaml:"tenant_id"`
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
		CallerInfo   string `yaml:"caller_info"`

		// Microsoft endpoints, mirroring the values Microsoft's reference SCEP
		// validation library makes configurable. The defaults target the
		// commercial cloud; override them for another Microsoft cloud or a mock.
		AuthorityHost string `yaml:"authority_host"` // Entra sign-in host
		GraphURL      string `yaml:"graph_url"`      // Graph base URL and scope base
		ResourceURL   string `yaml:"resource_url"`   // Intune token scope base
		AppID         string `yaml:"app_id"`         // Intune service principal app ID
	} `yaml:"intune"`
}

// Default Microsoft endpoints (commercial cloud).
const (
	DefaultAuthorityHost = "https://login.microsoftonline.com/"
	DefaultGraphURL      = "https://graph.microsoft.com/"
	DefaultResourceURL   = "https://api.manage.microsoft.com/"
	DefaultAppID         = "0000000a-0000-0000-c000-000000000000"
)

// Load reads and validates a YAML config file, applying defaults and env
// overrides for secrets (INTUNE_CLIENT_SECRET, SCEP_VALIDATE_SECRET,
// SCEP_NOTIFY_SECRET).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's own -config flag
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	cfg.applyEnv()
	cfg.normaliseEndpoints()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.Intune.CallerInfo == "" {
		c.Intune.CallerInfo = "step-ca-scep"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Intune.AuthorityHost == "" {
		c.Intune.AuthorityHost = DefaultAuthorityHost
	}
	if c.Intune.GraphURL == "" {
		c.Intune.GraphURL = DefaultGraphURL
	}
	if c.Intune.ResourceURL == "" {
		c.Intune.ResourceURL = DefaultResourceURL
	}
	if c.Intune.AppID == "" {
		c.Intune.AppID = DefaultAppID
	}
}

// normaliseEndpoints lower-cases each endpoint URL's scheme and host (both are
// case-insensitive) and makes it end with exactly one slash, so derived values
// ("<url>.default", "<url>v1.0/...") and comparisons with the defaults are
// correct however the URL was written. Values that don't parse as absolute URLs
// are left for Validate to reject.
func (c *Config) normaliseEndpoints() {
	for _, p := range []*string{&c.Intune.AuthorityHost, &c.Intune.GraphURL, &c.Intune.ResourceURL} {
		if u, err := url.Parse(*p); err == nil && u.Scheme != "" && u.Host != "" {
			u.Scheme = strings.ToLower(u.Scheme)
			u.Host = strings.ToLower(u.Host)
			*p = u.String()
		}
		*p = strings.TrimRight(*p, "/") + "/"
	}
}

func (c *Config) applyEnv() {
	if v := os.Getenv("INTUNE_CLIENT_SECRET"); v != "" {
		c.Intune.ClientSecret = v
	}
	if v := os.Getenv("INTUNE_TENANT_ID"); v != "" {
		c.Intune.TenantID = v
	}
	if v := os.Getenv("INTUNE_CLIENT_ID"); v != "" {
		c.Intune.ClientID = v
	}
	if v := os.Getenv("SCEP_VALIDATE_SECRET"); v != "" {
		c.Webhook.ValidateSecret = v
	}
	if v := os.Getenv("SCEP_NOTIFY_SECRET"); v != "" {
		c.Webhook.NotifySecret = v
	}
	if v := os.Getenv("INTUNE_AUTHORITY_HOST"); v != "" {
		c.Intune.AuthorityHost = v
	}
	if v := os.Getenv("INTUNE_GRAPH_URL"); v != "" {
		c.Intune.GraphURL = v
	}
	if v := os.Getenv("INTUNE_RESOURCE_URL"); v != "" {
		c.Intune.ResourceURL = v
	}
	if v := os.Getenv("INTUNE_APP_ID"); v != "" {
		c.Intune.AppID = v
	}
}

// Validate returns an error listing every missing required field.
func (c *Config) Validate() error {
	var missing []string
	// The webhook secrets are intentionally NOT required. An admin-managed
	// step-ca provisioner has a real per-webhook secret (set both here); a
	// ca.json-managed provisioner cannot store one (the field is json:"-") and
	// signs with an empty key, so an empty secret matches but disables real
	// authentication — acceptable only on a trusted network / for testing. main
	// logs a warning when either is empty.
	req := map[string]string{
		"intune.tenant_id":     c.Intune.TenantID,
		"intune.client_id":     c.Intune.ClientID,
		"intune.client_secret": c.Intune.ClientSecret,
	}
	for name, val := range req {
		if val == "" {
			missing = append(missing, name)
		}
	}
	if c.Server.TLS.Enabled {
		if c.Server.TLS.Cert == "" {
			missing = append(missing, "server.tls.cert")
		}
		if c.Server.TLS.Key == "" {
			missing = append(missing, "server.tls.key")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing required fields: %v", missing)
	}
	for _, e := range []struct{ key, env, val string }{
		{"intune.authority_host", "INTUNE_AUTHORITY_HOST", c.Intune.AuthorityHost},
		{"intune.graph_url", "INTUNE_GRAPH_URL", c.Intune.GraphURL},
		{"intune.resource_url", "INTUNE_RESOURCE_URL", c.Intune.ResourceURL},
	} {
		if err := checkHTTPSURL(e.key, e.env, e.val); err != nil {
			return err
		}
	}
	// app_id goes into the discovery URL path; a typo or stray character would
	// silently query another Graph resource.
	if !guidPattern.MatchString(c.Intune.AppID) {
		return fmt.Errorf("config: intune.app_id (env INTUNE_APP_ID) must be a GUID: %q", c.Intune.AppID)
	}
	return nil
}

var guidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// checkHTTPSURL reports an error unless val is an absolute https URL with a
// host and no credentials, query or fragment (scopes and paths are appended to
// it, and it is logged). The error names both the YAML key and the env var,
// since either may have set it, and never repeats a password.
func checkHTTPSURL(key, env, val string) error {
	u, err := url.Parse(val)
	if err != nil {
		return fmt.Errorf("config: %s (env %s) must be an absolute https URL", key, env)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("config: %s (env %s) must be an absolute https URL without credentials, query or fragment: %q",
			key, env, u.Redacted())
	}
	return nil
}

// Logger builds an *slog.Logger from the logging config. When Output is a file
// path, the file is opened for append (created if absent) and returned so the
// caller controls its lifetime; for stdout/stderr the returned closer is nil.
func (c *Config) Logger() (*slog.Logger, io.Closer, error) {
	var w io.Writer
	var closer io.Closer
	switch c.Logging.Output {
	case "stdout", "":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(c.Logging.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640) //nolint:gosec // G302: group-readable for log shippers
		if err != nil {
			return nil, nil, fmt.Errorf("config: open log file %q: %w", c.Logging.Output, err)
		}
		w, closer = f, f
	}

	var level slog.Level
	switch strings.ToLower(c.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, nil, fmt.Errorf("config: invalid logging.level %q", c.Logging.Level)
	}
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	switch strings.ToLower(c.Logging.Format) {
	case "json", "":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("config: invalid logging.format %q", c.Logging.Format)
	}
	return slog.New(h), closer, nil
}
