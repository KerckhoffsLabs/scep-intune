package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestApplyEnv(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "")
	maxRecords := fs.Int("max-records", 1000, "")
	env := map[string]string{"MOCK_BASE_URL": "https://m:8443", "MOCK_MAX_RECORDS": "7"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if err := applyEnv(fs, lookup); err != nil {
		t.Fatal(err)
	}
	if *baseURL != "https://m:8443" || *maxRecords != 7 {
		t.Fatalf("base-url=%q max-records=%d", *baseURL, *maxRecords)
	}
}

// An invalid value must stop the mock, not silently fall back to the default.
func TestApplyEnvRejectsInvalidValue(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Int("max-records", 1000, "")
	lookup := func(k string) (string, bool) { return "abc", k == "MOCK_MAX_RECORDS" }
	err := applyEnv(fs, lookup)
	if err == nil || !strings.Contains(err.Error(), "MOCK_MAX_RECORDS") {
		t.Fatalf("err = %v, want an error naming MOCK_MAX_RECORDS", err)
	}
}

// writeCert writes a throwaway self-signed certificate for 127.0.0.1 and its
// key as PEM files, and returns their paths and a client that trusts it.
func writeCert(t *testing.T) (certPath, keyPath string, client *http.Client) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intune-mock"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "mock.crt"), filepath.Join(dir, "mock.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	return certPath, keyPath, client
}

func noEnv(string) (string, bool) { return "", false }

func TestRunUsageErrors(t *testing.T) {
	cert, key, _ := writeCert(t)
	for name, tc := range map[string]struct {
		args []string
		env  func(string) (string, bool)
		want int
	}{
		"help":             {args: []string{"-h"}, want: 0},
		"unknown flag":     {args: []string{"-no-such-flag"}, want: 2},
		"missing required": {args: []string{"-cert", cert}, want: 2},
		"invalid base-url": {args: []string{"-cert", cert, "-key", key, "-base-url", "http://insecure"}, want: 2},
		"invalid env": {
			args: []string{"-cert", cert, "-key", key, "-base-url", "https://127.0.0.1:1"},
			env:  func(k string) (string, bool) { return "many", k == "MOCK_MAX_RECORDS" },
			want: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := tc.env
			if env == nil {
				env = noEnv
			}
			if code := run(t.Context(), tc.args, env, io.Discard, io.Discard); code != tc.want {
				t.Fatalf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

var addrPattern = regexp.MustCompile(`"addr":"([^"]+)"`)

// The mock serves over TLS, logs each request, and exits 0 once its context
// ends. Settings may come from the environment.
func TestRunServesAndShutsDown(t *testing.T) {
	cert, key, client := writeCert(t)
	env := map[string]string{"MOCK_CERT": cert, "MOCK_KEY": key}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-base-url", "https://intune-mock.example"}, lookup, &out, io.Discard)
	}()

	addr := waitAddr(t, &out, done)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v; log:\n%s", err, out.String())
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: status %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, want 0; log:\n%s", code, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}
	if log := out.String(); !strings.Contains(log, "client_id=(any)") || !strings.Contains(log, `"path":"/healthz"`) {
		t.Errorf("log lacks the startup config or the request:\n%s", log)
	}
}

// waitAddr returns the address the mock logged as bound, failing fast with its
// log if run exits first.
func waitAddr(t *testing.T, out *syncBuffer, done <-chan int) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("run exited early with %d; log:\n%s", code, out.String())
		default:
		}
		if m := addrPattern.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the mock never logged its address; log:\n%s", out.String())
	return ""
}

func TestRunListenFailure(t *testing.T) {
	cert, key, _ := writeCert(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	args := []string{"-listen", ln.Addr().String(), "-cert", cert, "-key", key, "-base-url", "https://intune-mock.example"}
	if code := run(t.Context(), args, noEnv, io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

func TestRunMissingCertificate(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-listen", "127.0.0.1:0", "-cert", filepath.Join(dir, "no.crt"), "-key", filepath.Join(dir, "no.key"), "-base-url", "https://intune-mock.example"}
	if code := run(t.Context(), args, noEnv, io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

// syncBuffer is a bytes.Buffer safe for the server goroutine to write while
// the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Shutdown drains: run does not return while a request is still in flight,
// and that request gets its response.
func TestRunDrainsInFlightRequests(t *testing.T) {
	cert, key, client := writeCert(t)
	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-cert", cert, "-key", key, "-base-url", "https://intune-mock.example"}, noEnv, &out, io.Discard)
	}()
	addr := waitAddr(t, &out, done)

	// A token request whose body is still arriving keeps its handler busy.
	body, upload := io.Pipe()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/tenant/oauth2/v2.0/token", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	type result struct {
		status int
		err    error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			got <- result{err: err}
			return
		}
		_ = resp.Body.Close()
		got <- result{status: resp.StatusCode}
	}()
	if _, err := io.WriteString(upload, "grant_type=client_credentials"); err != nil {
		t.Fatal(err)
	}
	for !strings.Contains(out.String(), `"path":"/tenant/oauth2/v2.0/token"`) {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-done:
		t.Fatalf("run returned %d with a request still in flight", code)
	case <-time.After(300 * time.Millisecond):
	}

	_ = upload.Close() // finish the body: the handler answers, the drain ends
	if r := <-got; r.err != nil || r.status == 0 {
		t.Fatalf("in-flight request: status %d err %v, want a response", r.status, r.err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit = %d, want 0; log:\n%s", code, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the drain")
	}
}
