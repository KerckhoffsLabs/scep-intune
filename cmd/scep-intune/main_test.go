package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearEnv blanks every variable config.Load or the Azure SDK reads, so a
// developer's or CI runner's environment cannot leak into a test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"INTUNE_CLIENT_SECRET", "INTUNE_TENANT_ID", "INTUNE_CLIENT_ID",
		"SCEP_VALIDATE_SECRET", "SCEP_NOTIFY_SECRET",
		"INTUNE_AUTHORITY_HOST", "INTUNE_GRAPH_URL", "INTUNE_RESOURCE_URL", "INTUNE_APP_ID",
		"AZURE_AUTHORITY_HOST",
	} {
		t.Setenv(k, "")
	}
}

var secret = base64.StdEncoding.EncodeToString([]byte("webhook-secret"))

// writeConfig writes a config whose logs go to a file in the test's directory,
// and returns the config path and the log path.
func writeConfig(t *testing.T, listen, extra string) (cfgPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "bridge.log")
	body := fmt.Sprintf(`server:
  listen: %q
webhook:
  validate_secret: %q
  notify_secret: %q
logging:
  output: %q
intune:
  tenant_id: "00000000-0000-0000-0000-000000000001"
  client_id: "client"
  client_secret: "secret"
%s`, listen, secret, secret, logPath, extra)
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, logPath
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunFlags(t *testing.T) {
	if code := run(t.Context(), []string{"-h"}, io.Discard); code != 0 {
		t.Errorf("-h: exit = %d, want 0", code)
	}
	if code := run(t.Context(), []string{"-no-such-flag"}, io.Discard); code != 2 {
		t.Errorf("unknown flag: exit = %d, want 2", code)
	}
}

func TestRunConfigErrors(t *testing.T) {
	clearEnv(t)
	cfg, _ := writeConfig(t, ":0", "")
	badLevel, _ := writeConfig(t, ":0", "")
	withLevel := strings.Replace(string(mustRead(t, badLevel)), "logging:\n", "logging:\n  level: loud\n", 1)
	if err := os.WriteFile(badLevel, []byte(withLevel), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"missing file":        {args: []string{"-config", filepath.Join(t.TempDir(), "nope.yaml")}, want: `"msg":"config"`},
		"bad validate secret": {args: []string{"-config", cfg}, env: map[string]string{"SCEP_VALIDATE_SECRET": "not base64!"}, want: "validate_secret must be base64"},
		"bad notify secret":   {args: []string{"-config", cfg}, env: map[string]string{"SCEP_NOTIFY_SECRET": "not base64!"}, want: "notify_secret must be base64"},
		"bad tenant":          {args: []string{"-config", cfg}, env: map[string]string{"INTUNE_TENANT_ID": "not a tenant!"}, want: "entra credential"},
		"logging setup":       {args: []string{"-config", badLevel}, want: "logging setup"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			var out bytes.Buffer
			if code := run(t.Context(), tc.args, &out); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			// Errors before the configured logger exists go to the bootstrap
			// logger; later ones go to the configured log file.
			if !strings.Contains(out.String(), tc.want) && !strings.Contains(logOf(t, tc.args), tc.want) {
				t.Errorf("no %q in output %q", tc.want, out.String())
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// logOf returns the log file next to the config named in args, or "" when there
// is none (the config failed to load before the file was opened).
func logOf(t *testing.T, args []string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(args[len(args)-1]), "bridge.log"))
	if err != nil {
		return ""
	}
	return string(b)
}

// The bridge serves until its context ends, then drains and exits 0. A
// non-Microsoft authority and a conflicting AZURE_AUTHORITY_HOST are both
// reported, since the client secret would go to that host.
func TestRunServesAndShutsDown(t *testing.T) {
	clearEnv(t)
	t.Setenv("AZURE_AUTHORITY_HOST", "https://login.example.invalid/")
	addr := freeAddr(t)
	cfg, logPath := writeConfig(t, addr, "  authority_host: \"https://entra-mock.example/\"\n")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", cfg}, io.Discard) }()

	waitHealthy(t, "http://"+addr+"/healthz", done)
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, want 0; log:\n%s", code, readLog(t, logPath))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}

	log := readLog(t, logPath)
	for _, want := range []string{
		"AZURE_AUTHORITY_HOST is ignored",
		"the Entra client secret is sent to a host that is not a Microsoft authority",
		"shutdown complete",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
}

func waitHealthy(t *testing.T, url string, done <-chan int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("run exited early with %d", code)
		default:
		}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never became healthy", url)
}

func TestRunListenFailure(t *testing.T) {
	clearEnv(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg, logPath := writeConfig(t, ln.Addr().String(), "")
	if code := run(t.Context(), []string{"-config", cfg}, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if log := readLog(t, logPath); !strings.Contains(log, "server failed to start") {
		t.Errorf("log lacks the start failure:\n%s", log)
	}
}

// With TLS enabled, an unreadable certificate stops the bridge at startup.
func TestRunTLSMissingCertificate(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	cfg, logPath := writeConfig(t, freeAddr(t), "")
	tlsCfg := fmt.Sprintf("server:\n  tls:\n    enabled: true\n    cert: %q\n    key: %q\n",
		filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
	// A second "server" mapping would be a YAML error: rewrite the listen line.
	body := strings.Replace(string(mustRead(t, cfg)), "server:\n", tlsCfg, 1)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(t.Context(), []string{"-config", cfg}, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if log := readLog(t, logPath); !strings.Contains(log, `"tls":true`) || !strings.Contains(log, "server failed to start") {
		t.Errorf("log lacks the TLS start failure:\n%s", log)
	}
}
