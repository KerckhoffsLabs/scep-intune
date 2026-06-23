// Package webhook implements the HTTP bridge that lets a vanilla step-ca
// SCEP provisioner validate enrollments against Microsoft Intune and report
// issuance results, using step-ca's webhook extension point.
//
// step-ca is configured with two webhooks on the SCEP provisioner:
//
//	SCEPCHALLENGE -> POST /validate  (validate the dynamic challenge with Intune)
//	NOTIFYING     -> POST /notify    (report issuance success/failure to Intune)
//
// Each request carries step-ca's webhook payload and an HMAC-SHA256 signature in
// X-Smallstep-Signature; the handler verifies it, then calls the Intune client.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/KerckhoffsLabs/scep-intune/internal/intune"
)

// maxBody caps a webhook request body. step-ca webhook payloads are small.
const maxBody = 1 << 20

// Validator is the Intune-facing behavior the handler needs. *intune.Client
// satisfies it.
type Validator interface {
	Validate(ctx context.Context, txnID string, csrDER []byte) error
	NotifySuccess(ctx context.Context, txnID string, csrDER []byte, cert *x509.Certificate) error
	NotifyFailure(ctx context.Context, txnID string, csrDER []byte, hResult int32, desc string) error
}

// request is the subset of step-ca's webhook.RequestBody this bridge consumes.
type request struct {
	X509CertificateRequest *rawCert `json:"x509CertificateRequest"`
	X509Certificate        *rawCert `json:"x509Certificate"`
	SCEPTransactionID      string   `json:"scepTransactionID"`
	SCEPErrorCode          int      `json:"scepErrorCode"`
	SCEPErrorDescription   string   `json:"scepErrorDescription"`
}

// rawCert holds the DER bytes step-ca includes for a CSR or certificate.
type rawCert struct {
	Raw []byte `json:"raw"`
}

// response is step-ca's webhook.ResponseBody (the fields this bridge sets).
type response struct {
	Allow bool `json:"allow"`
}

type handler struct {
	intune         Validator
	validateSecret []byte
	notifySecret   []byte
	log            *slog.Logger
}

// New returns an http.Handler serving /validate, /notify, and /healthz.
// validateSecret and notifySecret are the raw (decoded) HMAC keys for the
// SCEPCHALLENGE and NOTIFYING webhooks respectively — step-ca generates a
// distinct secret per webhook, so each endpoint is verified with its own.
func New(v Validator, validateSecret, notifySecret []byte, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &handler{intune: v, validateSecret: validateSecret, notifySecret: notifySecret, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", h.handleValidate)
	mux.HandleFunc("/notify", h.handleNotify)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// handleValidate bridges a SCEPCHALLENGE webhook to Intune challenge validation.
func (h *handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	req, ok := h.read(w, r, h.validateSecret)
	if !ok {
		return
	}
	if req.X509CertificateRequest == nil || len(req.X509CertificateRequest.Raw) == 0 {
		http.Error(w, "missing certificate request", http.StatusBadRequest)
		return
	}
	err := h.intune.Validate(r.Context(), req.SCEPTransactionID, req.X509CertificateRequest.Raw)
	switch {
	case err == nil:
		h.log.Info("intune validated challenge", "transactionID", req.SCEPTransactionID)
		writeAllow(w, true)
	case errors.Is(err, intune.ErrRejected):
		// Definitive rejection (bad/expired challenge): tell step-ca to deny.
		h.log.Warn("intune rejected challenge", "transactionID", req.SCEPTransactionID, "err", err)
		writeAllow(w, false)
	default:
		// Transient/transport failure: 5xx so step-ca fails the request and the
		// device retries, rather than treating it as a permanent rejection.
		h.log.Error("intune validate error", "transactionID", req.SCEPTransactionID, "err", err)
		http.Error(w, "intune upstream error", http.StatusBadGateway)
	}
}

// handleNotify bridges a NOTIFYING webhook to Intune success/failure reporting.
// A request carrying an issued certificate is a success; otherwise it's a failure.
func (h *handler) handleNotify(w http.ResponseWriter, r *http.Request) {
	req, ok := h.read(w, r, h.notifySecret)
	if !ok {
		return
	}
	var csrDER []byte
	if req.X509CertificateRequest != nil {
		csrDER = req.X509CertificateRequest.Raw
	}

	var err error
	if req.X509Certificate != nil && len(req.X509Certificate.Raw) > 0 {
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(req.X509Certificate.Raw); err != nil {
			http.Error(w, "invalid certificate", http.StatusBadRequest)
			return
		}
		err = h.intune.NotifySuccess(r.Context(), req.SCEPTransactionID, csrDER, cert)
	} else {
		err = h.intune.NotifyFailure(r.Context(), req.SCEPTransactionID, csrDER, int32(req.SCEPErrorCode), req.SCEPErrorDescription)
	}
	if err != nil {
		h.log.Error("intune notify error", "transactionID", req.SCEPTransactionID, "err", err)
		http.Error(w, "intune upstream error", http.StatusBadGateway)
		return
	}
	h.log.Info("intune notified", "transactionID", req.SCEPTransactionID, "success", req.X509Certificate != nil)
	writeAllow(w, true)
}

// read enforces POST, verifies the step-ca webhook signature, and decodes the
// body. It writes the error response and returns ok=false on any failure.
func (h *handler) read(w http.ResponseWriter, r *http.Request, secret []byte) (*request, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, false
	}
	if !verifySignature(secret, body, r.Header.Get("X-Smallstep-Signature")) {
		h.log.Warn("invalid webhook signature", "remote", r.RemoteAddr, "path", r.URL.Path)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return nil, false
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	h.log.Info("webhook request", "path", r.URL.Path, "transactionID", req.SCEPTransactionID)
	return &req, true
}

// verifySignature checks step-ca's X-Smallstep-Signature: hex(HMAC-SHA256(secret, body)).
func verifySignature(secret, body []byte, sigHex string) bool {
	got, err := hex.DecodeString(sigHex)
	if err != nil || len(got) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

func writeAllow(w http.ResponseWriter, allow bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{Allow: allow})
}
