package intune

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrRejected indicates Intune explicitly rejected the request (for example an
// expired or invalid challenge), as opposed to a transport/transient failure.
// Callers use errors.Is to distinguish a definitive rejection (do not retry)
// from a retryable error.
var ErrRejected = errors.New("intune: validation rejected")

// intuneHTTPTimeout bounds each Graph/Intune HTTP call. Without it a hung
// upstream would block the SCEP request goroutine indefinitely (the per-request
// context has no deadline of its own), so a slow Intune endpoint could exhaust
// server goroutines under load.
const intuneHTTPTimeout = 15 * time.Second

// tokenSource provides OAuth2 bearer tokens for a given scope.
type tokenSource interface {
	Token(ctx context.Context, scope string) (string, error)
}

type Client struct {
	http         *http.Client
	tokens       tokenSource
	callerInfo   string
	graphBaseURL string

	mu      sync.Mutex
	baseURI string // discovered ScepRequestValidationFEService URI
}

func New(tokens tokenSource, callerInfo string) *Client {
	return &Client{
		http:         &http.Client{Timeout: intuneHTTPTimeout},
		tokens:       tokens,
		callerInfo:   callerInfo,
		graphBaseURL: graphBaseURL,
	}
}

func (c *Client) discover(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.baseURI != "" {
		uri := c.baseURI
		c.mu.Unlock()
		return uri, nil
	}
	c.mu.Unlock()

	tok, err := c.tokens.Token(ctx, graphScope)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%sv1.0/servicePrincipals/appId=%s/endpoints", c.graphBaseURL, intuneAppID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Api-Version", graphAPIVersion)
	req.Header.Set("client-request-id", uuid.NewString())
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("intune: discovery returned HTTP %d", resp.StatusCode)
	}
	var disc discoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return "", err
	}
	for _, e := range disc.Value {
		if e.ProviderName == validationServiceName {
			c.mu.Lock()
			// Re-check under the lock: a concurrent discover may have
			// already stored a URI while we were doing the HTTP call.
			if c.baseURI == "" {
				c.baseURI = e.URI
			}
			uri := c.baseURI
			c.mu.Unlock()
			return uri, nil
		}
	}
	return "", fmt.Errorf("intune: %s endpoint not found in discovery", validationServiceName)
}

func (c *Client) post(ctx context.Context, path string, payload any) ([]byte, int, error) {
	base, err := c.discover(ctx)
	if err != nil {
		return nil, 0, err
	}
	tok, err := c.tokens.Token(ctx, intuneScope)
	if err != nil {
		return nil, 0, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Api-Version", apiVersion)
	req.Header.Set("client-request-id", uuid.NewString())
	req.Header.Set("User-Agent", c.callerInfo)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	// A non-2xx is a transport/auth/throttling failure, distinct from a
	// validation rejection (which Intune returns as HTTP 200 with a code).
	// Surfacing it as an error keeps callers from misparsing an error body.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return rb, resp.StatusCode, fmt.Errorf("intune: %s returned HTTP %d", path, resp.StatusCode)
	}
	return rb, resp.StatusCode, nil
}

// Validate returns nil iff Intune replies code == "Success".
func (c *Client) Validate(ctx context.Context, txnID string, csrDER []byte) error {
	rb, _, err := c.post(ctx, pathValidate, validateBody{Request: reqInfo{
		TransactionID:      txnID,
		CertificateRequest: csrDER,
		CallerInfo:         c.callerInfo,
	}})
	if err != nil {
		return err
	}
	var cr codeResponse
	if err := json.Unmarshal(rb, &cr); err != nil {
		return fmt.Errorf("intune: decode validate response: %w", err)
	}
	if cr.Code != "Success" {
		return fmt.Errorf("%w: %s: %s", ErrRejected, cr.Code, cr.ErrorDescription)
	}
	return nil
}

// NotifySuccess reports a successful issuance to Intune.
func (c *Client) NotifySuccess(ctx context.Context, txnID string, csrDER []byte, cert *x509.Certificate) error {
	_, _, err := c.post(ctx, pathNotifySuccess, notifyBody{Notification: notifyInfo{
		TransactionID:                txnID,
		CertificateRequest:           csrDER,
		CertificateThumbprint:        thumbprintSHA1(cert),
		CertificateSerialNumber:      serialNumber(cert),
		CertificateExpirationDateUtc: expiryUTC(cert),
		IssuingCertificateAuthority:  cert.Issuer.CommonName,
		CallerInfo:                   c.callerInfo,
	}})
	return err
}

// NotifyFailure reports a failed issuance to Intune. hResult is a 32-bit
// HRESULT-style code; desc is truncated to 255 chars.
func (c *Client) NotifyFailure(ctx context.Context, txnID string, csrDER []byte, hResult int32, desc string) error {
	if len(desc) > 255 {
		desc = desc[:255]
	}
	_, _, err := c.post(ctx, pathNotifyFailure, notifyBody{Notification: notifyInfo{
		TransactionID:      txnID,
		CertificateRequest: csrDER,
		HResult:            hResult,
		ErrorDescription:   desc,
		CallerInfo:         c.callerInfo,
	}})
	return err
}
