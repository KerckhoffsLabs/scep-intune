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

const minimalIntune = `
intune:
  tenant_id: "t"
  client_id: "c"
  client_secret: "s"
`

func TestEndpointDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalIntune))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"authority_host": "https://login.microsoftonline.com/",
		"graph_url":      "https://graph.microsoft.com/",
		"resource_url":   "https://api.manage.microsoft.com/",
		"app_id":         "0000000a-0000-0000-c000-000000000000",
	}
	got := map[string]string{
		"authority_host": cfg.Intune.AuthorityHost,
		"graph_url":      cfg.Intune.GraphURL,
		"resource_url":   cfg.Intune.ResourceURL,
		"app_id":         cfg.Intune.AppID,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}

func TestEndpointFromFileAndEnv(t *testing.T) {
	t.Setenv("INTUNE_RESOURCE_URL", "https://api.manage.microsoft.us/")
	t.Setenv("INTUNE_APP_ID", "11111111-2222-3333-4444-555555555555")
	cfg, err := Load(writeConfig(t, minimalIntune+"  graph_url: https://graph.microsoft.us/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != "https://graph.microsoft.us/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
	if cfg.Intune.ResourceURL != "https://api.manage.microsoft.us/" {
		t.Errorf("resource_url = %q", cfg.Intune.ResourceURL)
	}
	if cfg.Intune.AppID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("app_id = %q", cfg.Intune.AppID)
	}
}

func TestEndpointTrailingSlashNormalised(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalIntune+
		"  authority_host: https://login.microsoftonline.us\n"+
		"  graph_url: https://graph.microsoft.us//\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.AuthorityHost != "https://login.microsoftonline.us/" {
		t.Errorf("authority_host = %q", cfg.Intune.AuthorityHost)
	}
	if cfg.Intune.GraphURL != "https://graph.microsoft.us/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

func TestEndpointRejectsNonHTTPS(t *testing.T) {
	for _, key := range []string{"authority_host", "graph_url", "resource_url"} {
		for _, val := range []string{"http://x/", "graph.microsoft.com", "https://"} {
			t.Run(key+"="+val, func(t *testing.T) {
				_, err := Load(writeConfig(t, minimalIntune+"  "+key+": \""+val+"\"\n"))
				if err == nil || !strings.Contains(err.Error(), "intune."+key) {
					t.Fatalf("want error naming intune.%s, got %v", key, err)
				}
			})
		}
	}
}

func TestEndpointEmptyEnvKeepsFile(t *testing.T) {
	t.Setenv("INTUNE_GRAPH_URL", "")
	cfg, err := Load(writeConfig(t, minimalIntune+"  graph_url: https://g.example/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != "https://g.example/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

// The documented example must stay loadable (its secrets come from the env).
func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("INTUNE_TENANT_ID", "t")
	t.Setenv("INTUNE_CLIENT_ID", "c")
	t.Setenv("INTUNE_CLIENT_SECRET", "s")
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.GraphURL != DefaultGraphURL {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

// Hosts are case-insensitive: an upper-case default must still count as the
// default (so instance discovery stays on) and derive the same scopes.
func TestEndpointHostLowercased(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalIntune+
		"  authority_host: HTTPS://LOGIN.microsoftonline.com\n"+
		"  graph_url: https://Graph.Microsoft.com/Path/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Intune.AuthorityHost != DefaultAuthorityHost {
		t.Errorf("authority_host = %q, want %q", cfg.Intune.AuthorityHost, DefaultAuthorityHost)
	}
	// Only scheme and host are case-insensitive; the path is kept as written.
	if cfg.Intune.GraphURL != "https://graph.microsoft.com/Path/" {
		t.Errorf("graph_url = %q", cfg.Intune.GraphURL)
	}
}

func TestEndpointRejectsQueryAndFragment(t *testing.T) {
	for _, val := range []string{"https://graph.microsoft.us/?x=1", "https://graph.microsoft.us/#frag"} {
		_, err := Load(writeConfig(t, minimalIntune+"  graph_url: \""+val+"\"\n"))
		if err == nil || !strings.Contains(err.Error(), "intune.graph_url") {
			t.Errorf("%s: want error naming intune.graph_url, got %v", val, err)
		}
	}
}

// The value may come from the environment, so the error names both sources.
func TestEndpointErrorNamesEnvVar(t *testing.T) {
	t.Setenv("INTUNE_GRAPH_URL", "http://insecure/")
	_, err := Load(writeConfig(t, minimalIntune))
	if err == nil || !strings.Contains(err.Error(), "INTUNE_GRAPH_URL") {
		t.Fatalf("want error naming INTUNE_GRAPH_URL, got %v", err)
	}
}

func TestAppIDMustBeGUID(t *testing.T) {
	for val, ok := range map[string]bool{
		"0000000a-0000-0000-c000-000000000000":  true,
		"0000000A-0000-0000-C000-000000000000":  true,
		"0000000a-0000-0000-c000-000000000000/": false,
		"x?y":                                   false,
		"abc":                                   false,
	} {
		_, err := Load(writeConfig(t, minimalIntune+"  app_id: \""+val+"\"\n"))
		if (err == nil) != ok {
			t.Errorf("app_id %q: err = %v, want ok=%v", val, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "INTUNE_APP_ID") {
			t.Errorf("app_id %q: error %q should name INTUNE_APP_ID", val, err)
		}
	}
}

// Credentials in a URL would end up in logs and token scopes.
func TestEndpointRejectsUserinfo(t *testing.T) {
	_, err := Load(writeConfig(t, minimalIntune+"  graph_url: \"https://user:pass@graph.example/\"\n"))
	if err == nil || !strings.Contains(err.Error(), "intune.graph_url") {
		t.Fatalf("want error naming intune.graph_url, got %v", err)
	}
	if strings.Contains(err.Error(), "pass") {
		t.Fatalf("error leaks the password: %v", err)
	}
}
