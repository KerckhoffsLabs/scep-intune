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
			if code := run(t.Context(), tc.args, env, io.Discard); code != tc.want {
				t.Fatalf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

// The mock serves over TLS, logs each request, and exits 0 once its context
// ends. Settings may come from the environment.
func TestRunServesAndShutsDown(t *testing.T) {
	cert, key, client := writeCert(t)
	addr := freeAddr(t)
	env := map[string]string{"MOCK_CERT": cert, "MOCK_KEY": key}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	var out syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", addr, "-base-url", "https://" + addr}, lookup, &out)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("mock never became healthy: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
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

func TestRunMissingCertificate(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-listen", freeAddr(t), "-cert", filepath.Join(dir, "no.crt"), "-key", filepath.Join(dir, "no.key"), "-base-url", "https://127.0.0.1:1"}
	if code := run(t.Context(), args, noEnv, io.Discard); code != 1 {
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
