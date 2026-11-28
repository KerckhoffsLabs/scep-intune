package webhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

type fakeIntune struct {
	validateErr error
	notifyErr   error
	lastCert    *x509.Certificate
	calls       []string
	lastTxn     string
	lastCSR     []byte
}

func (f *fakeIntune) Validate(_ context.Context, txn string, csr []byte) error {
	f.calls = append(f.calls, "validate")
	f.lastTxn, f.lastCSR = txn, csr
	return f.validateErr
}

func (f *fakeIntune) NotifySuccess(_ context.Context, txn string, csr []byte, cert *x509.Certificate) error {
	f.calls = append(f.calls, "success")
	f.lastTxn, f.lastCSR, f.lastCert = txn, csr, cert
	return f.notifyErr
}

func (f *fakeIntune) NotifyFailure(_ context.Context, _ string, _ []byte, _ int32, _ string) error {
	f.calls = append(f.calls, "failure")
	return f.notifyErr
}

var testSecret = []byte("test-secret")

func signed(path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	mac := hmac.New(sha256.New, testSecret)
	mac.Write(b)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(mac.Sum(nil)))
	return req
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestValidateAllow(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": []byte("csr")},
		"scepTransactionID":      "txn-1",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Allow {
		t.Error("allow = false, want true")
	}
	if fi.lastTxn != "txn-1" || string(fi.lastCSR) != "csr" {
		t.Errorf("txn=%q csr=%q", fi.lastTxn, fi.lastCSR)
	}
}

func TestValidateRejectedDenies(t *testing.T) {
	fi := &fakeIntune{validateErr: fmt.Errorf("%w: ChallengeExpired", intune.ErrRejected)}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": []byte("csr")},
		"scepTransactionID":      "txn-2",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with allow=false", rec.Code)
	}
	var resp response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allow {
		t.Error("allow = true, want false on rejection")
	}
}

func TestValidateTransientErrorIs502(t *testing.T) {
	fi := &fakeIntune{validateErr: fmt.Errorf("intune: returned HTTP 503")}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/validate", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": []byte("csr")},
		"scepTransactionID":      "txn-3",
	}))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 on transient error", rec.Code)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	fi := &fakeIntune{}
	req := signed("/validate", map[string]any{"scepTransactionID": "x"})
	req.Header.Set("X-Smallstep-Signature", "deadbeef") // tamper
	rec := do(New(fi, testSecret, testSecret, nil), req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called despite bad signature: %v", fi.calls)
	}
}

func TestNotifyFailureWhenNoCert(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/notify", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": []byte("csr")},
		"scepTransactionID":      "txn-4",
		"scepErrorCode":          5,
		"scepErrorDescription":   "boom",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if got := strings.Join(fi.calls, ","); got != "failure" {
		t.Errorf("calls = %s, want failure", got)
	}
}

// step-ca's SCEP error code is an int; Intune's hResult is an int32. A value
// out of range must not wrap around into an unrelated code.
func TestHResult(t *testing.T) {
	for in, want := range map[int]int32{
		0:                 0,
		2:                 2,
		-2147024809:       -2147024809,
		math.MaxInt32:     math.MaxInt32,
		math.MaxInt32 + 1: hResultFail,
		math.MinInt32 - 1: hResultFail,
	} {
		if got := hResult(in); got != want {
			t.Errorf("hResult(%d) = %d, want %d", in, got, want)
		}
	}
}

// testCertDER returns a self-signed certificate, as step-ca's NOTIFYING webhook
// carries the issued one.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNotifySuccessWithCert(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/notify", map[string]any{
		"x509CertificateRequest": map[string]any{"raw": []byte("csr")},
		"x509Certificate":        map[string]any{"raw": testCertDER(t)},
		"scepTransactionID":      "txn-5",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if got := strings.Join(fi.calls, ","); got != "success" {
		t.Fatalf("calls = %s, want success", got)
	}
	if fi.lastTxn != "txn-5" || string(fi.lastCSR) != "csr" || fi.lastCert == nil || fi.lastCert.SerialNumber.Int64() != 42 {
		t.Errorf("txn=%q csr=%q cert=%v", fi.lastTxn, fi.lastCSR, fi.lastCert)
	}
}

// A certificate step-ca sends must parse; Intune is not told anything otherwise.
func TestNotifyInvalidCertificate(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(New(fi, testSecret, testSecret, nil), signed("/notify", map[string]any{
		"x509Certificate":   map[string]any{"raw": []byte("not a certificate")},
		"scepTransactionID": "txn-6",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called for an invalid certificate: %v", fi.calls)
	}
}

// An Intune failure while notifying is a 502, so step-ca records the failure.
func TestNotifyUpstreamErrorIs502(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"success": {"x509Certificate": map[string]any{"raw": testCertDER(t)}, "scepTransactionID": "txn-7"},
		"failure": {"scepTransactionID": "txn-8", "scepErrorCode": 2},
	} {
		t.Run(name, func(t *testing.T) {
			fi := &fakeIntune{notifyErr: errors.New("intune: returned HTTP 503")}
			if rec := do(New(fi, testSecret, testSecret, nil), signed("/notify", body)); rec.Code != http.StatusBadGateway {
				t.Fatalf("code = %d, want 502", rec.Code)
			}
		})
	}
}

// /notify is verified with its own secret: a request signed with the
// /validate secret is refused.
func TestNotifyUsesItsOwnSecret(t *testing.T) {
	fi := &fakeIntune{}
	rec := do(New(fi, testSecret, []byte("other-secret"), nil), signed("/notify", map[string]any{"scepTransactionID": "txn-9"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called despite the wrong secret: %v", fi.calls)
	}
}

func TestValidateMissingCSR(t *testing.T) {
	fi := &fakeIntune{}
	for name, body := range map[string]map[string]any{
		"absent": {"scepTransactionID": "txn-10"},
		"empty":  {"scepTransactionID": "txn-11", "x509CertificateRequest": map[string]any{"raw": []byte{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := do(New(fi, testSecret, testSecret, nil), signed("/validate", body)); rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400", rec.Code)
			}
		})
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called without a CSR: %v", fi.calls)
	}
}

func TestOnlyPOST(t *testing.T) {
	for _, path := range []string{"/validate", "/notify"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		if rec := do(New(&fakeIntune{}, testSecret, testSecret, nil), req); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: code = %d, want 405", path, rec.Code)
		}
	}
}

// A correctly signed body that isn't JSON is a 400, not a crash or an allow.
func TestInvalidJSONBody(t *testing.T) {
	body := []byte("{not json")
	mac := hmac.New(sha256.New, testSecret)
	mac.Write(body)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("X-Smallstep-Signature", hex.EncodeToString(mac.Sum(nil)))
	fi := &fakeIntune{}
	if rec := do(New(fi, testSecret, testSecret, nil), req); rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	if len(fi.calls) != 0 {
		t.Errorf("intune called for an invalid body: %v", fi.calls)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestBodyReadError(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/validate", failingReader{})
	if rec := do(New(&fakeIntune{}, testSecret, testSecret, nil), req); rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestMissingSignatureRejected(t *testing.T) {
	req := signed("/validate", map[string]any{"scepTransactionID": "x"})
	req.Header.Del("X-Smallstep-Signature")
	if rec := do(New(&fakeIntune{}, testSecret, testSecret, nil), req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	if rec := do(New(&fakeIntune{}, testSecret, testSecret, nil), req); rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}
