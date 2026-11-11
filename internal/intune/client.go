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
	"net/url"
	"strings"
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

// tokenSource provides OAuth2 bearer tokens for a given scope. The name mirrors
// the standard library's oauth2.TokenSource, which is the idiomatic name for this
// abstraction, so the -er-suffix convention (sonar godre:S8196) does not apply.
type tokenSource interface { // nosonar S8196 -- mirrors stdlib oauth2.TokenSource
	Token(ctx context.Context, scope string) (string, error)
}

// Endpoints are the Microsoft addresses the client uses. Each URL must end
// with "/": scopes are derived as "<url>.default" and discovery is fetched from
// "<GraphURL>v1.0/servicePrincipals/appId=<AppID>/endpoints". The Intune
// ScepActions address itself comes from discovery.
type Endpoints struct {
	GraphURL    string // Graph base URL, also the base of the Graph token scope
	ResourceURL string // base of the Intune token scope
	AppID       string // Intune service principal app ID
}

// Client calls Microsoft Graph (service discovery) and the Intune SCEP
// validation API on behalf of the webhook handler.
type Client struct {
	http       *http.Client
	tokens     tokenSource
	callerInfo string
	ep         Endpoints

	mu      sync.Mutex
	baseURI string // discovered ScepRequestValidationFEService URI
}

// New returns a Client that authenticates with tokens, identifies itself to
// Intune as callerInfo, and talks to the Microsoft endpoints in ep.
func New(tokens tokenSource, callerInfo string, ep Endpoints) *Client {
	return &Client{
		http:       &http.Client{Timeout: intuneHTTPTimeout},
		tokens:     tokens,
		callerInfo: callerInfo,
		ep:         ep,
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

	tok, err := c.tokens.Token(ctx, c.ep.GraphURL+".default")
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%sv1.0/servicePrincipals/appId=%s/endpoints", c.ep.GraphURL, c.ep.AppID)
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
			if err := c.checkServiceURI(e.URI); err != nil {
				return "", err
			}
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

// checkServiceURI refuses a discovered service address the bridge must not send
// its Intune token to: it must be an absolute URL, and https whenever the Graph
// URL is (always in production, where config only accepts https; tests may run
// Graph over plain http).
func (c *Client) checkServiceURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return fmt.Errorf("intune: discovery returned an invalid %s URI %q", validationServiceName, uri)
	}
	if strings.HasPrefix(c.ep.GraphURL, "https://") && u.Scheme != "https" {
		return fmt.Errorf("intune: discovery returned a non-https %s URI %q", validationServiceName, uri)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, payload any) ([]byte, int, error) {
	base, err := c.discover(ctx)
	if err != nil {
		return nil, 0, err
	}
	tok, err := c.tokens.Token(ctx, c.ep.ResourceURL+".default")
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
