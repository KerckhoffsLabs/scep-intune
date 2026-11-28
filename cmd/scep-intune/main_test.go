package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
		"AZURE_AUTHORITY_HOST", "SCEP_ALLOW_UNSIGNED",
	} {
		t.Setenv(k, "")
	}
}

// Distinct, recognisable secrets: each endpoint must accept only its own, and
// none may appear in the log.
const (
	validateKey  = "sentinel-validate-key"
	notifyKey    = "sentinel-notify-key"
	clientSecret = "sentinel-client-secret"
)

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
  client_secret: %q
%s`, listen, b64(validateKey), b64(notifyKey), logPath, clientSecret, extra)
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, logPath
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// rewrite replaces from with to in the file at path.
func rewrite(t *testing.T, path, from, to string) {
	t.Helper()
	body := readFile(t, path)
	if !strings.Contains(body, from) {
		t.Fatalf("%s lacks %q", path, from)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(body, from, to, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readFile returns the file's content, or "" when it does not exist (a config
// that failed to load never opens its log file).
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temp file
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunFlags(t *testing.T) {
	var usage bytes.Buffer
	if code := run(t.Context(), []string{"-h"}, io.Discard, &usage); code != 0 {
		t.Errorf("-h: exit = %d, want 0", code)
	}
	if !strings.Contains(usage.String(), "-config") {
		t.Errorf("-h: usage %q lacks -config", usage.String())
	}
	if code := run(t.Context(), []string{"-no-such-flag"}, io.Discard, io.Discard); code != 2 {
		t.Errorf("unknown flag: exit = %d, want 2", code)
	}
}

func TestRunConfigErrors(t *testing.T) {
	clearEnv(t)
	cfg, _ := writeConfig(t, "127.0.0.1:0", "")
	badLevel, _ := writeConfig(t, "127.0.0.1:0", "")
	rewrite(t, badLevel, "logging:\n", "logging:\n  level: loud\n")

	for _, tc := range []struct {
		name string
		cfg  string
		env  map[string]string
		want string
	}{
		{name: "missing file", cfg: filepath.Join(t.TempDir(), "nope.yaml"), want: `"msg":"config"`},
		{name: "bad validate secret", cfg: cfg, env: map[string]string{"SCEP_VALIDATE_SECRET": "not base64!"}, want: "validate_secret must be base64"},
		{name: "bad notify secret", cfg: cfg, env: map[string]string{"SCEP_NOTIFY_SECRET": "not base64!"}, want: "notify_secret must be base64"},
		{name: "bad tenant", cfg: cfg, env: map[string]string{"INTUNE_TENANT_ID": "not a tenant!"}, want: "entra credential"},
		{name: "logging setup", cfg: badLevel, want: "logging setup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			var out bytes.Buffer
			if code := run(t.Context(), []string{"-config", tc.cfg}, &out, io.Discard); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			// Errors before the configured logger exists go to the bootstrap
			// logger; later ones go to the configured log file.
			logged := out.String() + readFile(t, filepath.Join(filepath.Dir(tc.cfg), "bridge.log"))
			if !strings.Contains(logged, tc.want) {
				t.Errorf("no %q in the bootstrap output or log file:\n%s", tc.want, logged)
			}
		})
	}
}

var addrPattern = regexp.MustCompile(`"msg":"starting".*"addr":"([^"]+)"`)

// startBridge runs the bridge until the test ends and returns the address it
// bound, read from its log, and the channel run's exit code arrives on.
func startBridge(ctx context.Context, t *testing.T, cfg, logPath string) (string, <-chan int) {
	t.Helper()
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", cfg}, io.Discard, io.Discard) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("run exited early with %d; log:\n%s", code, readFile(t, logPath))
		default:
		}
		if m := addrPattern.FindStringSubmatch(readFile(t, logPath)); m != nil {
			return m[1], done
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the bridge never logged its address; log:\n%s", readFile(t, logPath))
	return "", nil
}

// post sends body to the bridge, signed with key, and returns the status.
func post(t *testing.T, addr, path, key, body string) int {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(body))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The bridge serves until its context ends, then drains and exits 0. Each
// webhook accepts only its own secret, and no secret reaches the log. A
// non-Microsoft authority and a conflicting AZURE_AUTHORITY_HOST are both
// reported, since the client secret would go to that host.
func TestRunServesAndShutsDown(t *testing.T) {
	clearEnv(t)
	t.Setenv("AZURE_AUTHORITY_HOST", "https://login.example.invalid/")
	cfg, logPath := writeConfig(t, "127.0.0.1:0", "  authority_host: \"https://entra-mock.example/\"\n")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, done := startBridge(ctx, t, cfg, logPath)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: status %d", resp.StatusCode)
	}

	// The bodies fail validation before Intune is called (no CSR; a
	// certificate that doesn't parse), so a 400 proves the signature passed
	// without any request leaving the test.
	const noCSR, badCert = `{}`, `{"x509Certificate":{"raw":"AAAA"}}`
	for _, tc := range []struct {
		path, key, body string
		want            int
	}{
		{"/validate", validateKey, noCSR, http.StatusBadRequest},
		{"/validate", notifyKey, noCSR, http.StatusUnauthorized},
		{"/notify", notifyKey, badCert, http.StatusBadRequest},
		{"/notify", validateKey, badCert, http.StatusUnauthorized},
	} {
		if got := post(t, addr, tc.path, tc.key, tc.body); got != tc.want {
			t.Errorf("%s signed with %s: status %d, want %d", tc.path, tc.key, got, tc.want)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, want 0; log:\n%s", code, readFile(t, logPath))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}

	log := readFile(t, logPath)
	for _, want := range []string{
		"AZURE_AUTHORITY_HOST is ignored",
		"the Entra client secret is sent to a host that is not a Microsoft authority",
		"invalid webhook signature",
		"shutdown complete",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	for _, s := range []string{validateKey, notifyKey, clientSecret, b64(validateKey), b64(notifyKey)} {
		if strings.Contains(log, s) {
			t.Errorf("log contains the secret %q:\n%s", s, log)
		}
	}
}

func TestRunListenFailure(t *testing.T) {
	clearEnv(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg, logPath := writeConfig(t, ln.Addr().String(), "")
	if code := run(t.Context(), []string{"-config", cfg}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if log := readFile(t, logPath); !strings.Contains(log, "server failed to start") {
		t.Errorf("log lacks the start failure:\n%s", log)
	}
}

// An empty webhook secret is anyone's signature: the bridge refuses to start
// with one unless webhook.allow_unsigned is set.
func TestRunRefusesEmptySecret(t *testing.T) {
	clearEnv(t)
	cfg, _ := writeConfig(t, "127.0.0.1:0", "")
	rewrite(t, cfg, b64(notifyKey), "")
	var out bytes.Buffer
	if code := run(t.Context(), []string{"-config", cfg}, &out, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "webhook.notify_secret") || !strings.Contains(out.String(), "webhook.allow_unsigned") {
		t.Errorf("bootstrap log lacks the refusal:\n%s", out.String())
	}
}

// With webhook.allow_unsigned, the bridge starts with an empty secret, warns
// about that endpoint only, and serves it unauthenticated as configured.
func TestRunAllowUnsignedWarns(t *testing.T) {
	clearEnv(t)
	cfg, logPath := writeConfig(t, "127.0.0.1:0", "")
	rewrite(t, cfg, b64(notifyKey), "")
	rewrite(t, cfg, "webhook:\n", "webhook:\n  allow_unsigned: true\n")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, done := startBridge(ctx, t, cfg, logPath)
	// /notify accepts an empty-key signature; /validate still needs its secret.
	const badCert = `{"x509Certificate":{"raw":"AAAA"}}`
	if got := post(t, addr, "/notify", "", badCert); got != http.StatusBadRequest {
		t.Errorf("/notify with an empty-key signature: status %d, want 400 (signature accepted)", got)
	}
	if got := post(t, addr, "/validate", "", `{}`); got != http.StatusUnauthorized {
		t.Errorf("/validate with an empty-key signature: status %d, want 401", got)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}

	log := readFile(t, logPath)
	if !strings.Contains(log, `"endpoint":"/notify"`) || !strings.Contains(log, "NOT authenticated") {
		t.Errorf("log lacks the warning for /notify:\n%s", log)
	}
	if strings.Contains(log, `"endpoint":"/validate"`) {
		t.Errorf("log warns about /validate, whose secret is set:\n%s", log)
	}
}

// With TLS enabled, an unreadable certificate stops the bridge at startup.
func TestRunTLSMissingCertificate(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	cfg, logPath := writeConfig(t, "127.0.0.1:0", "")
	// A second "server" mapping would be a YAML error: extend the existing one.
	rewrite(t, cfg, "server:\n", fmt.Sprintf("server:\n  tls:\n    enabled: true\n    cert: %q\n    key: %q\n",
		filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")))
	if code := run(t.Context(), []string{"-config", cfg}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if log := readFile(t, logPath); !strings.Contains(log, `"tls":true`) || !strings.Contains(log, "server failed to start") {
		t.Errorf("log lacks the TLS start failure:\n%s", log)
	}
}
