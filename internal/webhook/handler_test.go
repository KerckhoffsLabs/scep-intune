package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

type fakeIntune struct {
	validateErr error
	calls       []string
	lastTxn     string
	lastCSR     []byte
}

func (f *fakeIntune) Validate(_ context.Context, txn string, csr []byte) error {
	f.calls = append(f.calls, "validate")
	f.lastTxn, f.lastCSR = txn, csr
	return f.validateErr
}

func (f *fakeIntune) NotifySuccess(_ context.Context, _ string, _ []byte, _ *x509.Certificate) error {
	f.calls = append(f.calls, "success")
	return nil
}

func (f *fakeIntune) NotifyFailure(_ context.Context, _ string, _ []byte, _ int32, _ string) error {
	f.calls = append(f.calls, "failure")
	return nil
}

var testSecret = []byte("test-secret")

func signed(path string, body any) *http.Request {
	b, _ := json.Marshal(body)
	mac := hmac.New(sha256.New, testSecret)
	mac.Write(b)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
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
