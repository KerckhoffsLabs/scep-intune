package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidWithDefaults(t *testing.T) {
	p := writeConfig(t, `
server:
  listen: ":9090"
webhook:
  secret: "c2VjcmV0"
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":9090" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Intune.CallerInfo != "step-ca-scep" {
		t.Errorf("callerInfo default = %q", cfg.Intune.CallerInfo)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("logging format default = %q", cfg.Logging.Format)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("INTUNE_CLIENT_SECRET", "env-secret")
	t.Setenv("SCEP_VALIDATE_SECRET", "env-validate")
	t.Setenv("SCEP_NOTIFY_SECRET", "env-notify")
	p := writeConfig(t, `
intune:
  tenant_id: "t"
  client_id: "c"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.ClientSecret != "env-secret" {
		t.Errorf("client secret = %q", cfg.Intune.ClientSecret)
	}
	if cfg.Webhook.ValidateSecret != "env-validate" {
		t.Errorf("validate secret = %q", cfg.Webhook.ValidateSecret)
	}
	if cfg.Webhook.NotifySecret != "env-notify" {
		t.Errorf("notify secret = %q", cfg.Webhook.NotifySecret)
	}
}

func TestValidateMissingRequired(t *testing.T) {
	p := writeConfig(t, "server:\n  listen: \":8080\"\n")
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
	for _, want := range []string{"intune.tenant_id", "intune.client_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestTLSRequiresCertKey(t *testing.T) {
	p := writeConfig(t, `
webhook:
  secret: "c2VjcmV0"
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
server:
  tls:
    enabled: true
`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "server.tls.cert") {
		t.Fatalf("err = %v, want tls.cert required", err)
	}
}
