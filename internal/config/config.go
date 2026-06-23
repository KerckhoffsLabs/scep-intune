// Package config defines the webhook-bridge configuration and its validation.
package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
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
	} `yaml:"intune"`
}

// Load reads and validates a YAML config file, applying defaults and env
// overrides for secrets (INTUNE_CLIENT_SECRET, SCEP_VALIDATE_SECRET,
// SCEP_NOTIFY_SECRET).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	cfg.applyEnv()
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
		f, err := os.OpenFile(c.Logging.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
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
