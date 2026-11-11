package intunemock

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const intuneAppID = "0000000a-0000-0000-c000-000000000000"

func do(t *testing.T, method, u, token string, body io.Reader, contentType string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestHealthz(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	if code, _ := do(t, http.MethodGet, srv.URL+"/healthz", "", nil, ""); code != http.StatusOK {
		t.Fatalf("healthz = %d", code)
	}
}

func TestOIDCMetadata(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	code, b := do(t, http.MethodGet, srv.URL+"/tenant-1/v2.0/.well-known/openid-configuration", "", nil, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	var md map[string]any
	if err := json.Unmarshal(b, &md); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"token_endpoint":         srv.URL + "/tenant-1/oauth2/v2.0/token",
		"authorization_endpoint": srv.URL + "/tenant-1/oauth2/v2.0/authorize",
		"issuer":                 srv.URL + "/tenant-1/v2.0",
	}
	for k, v := range want {
		if md[k] != v {
			t.Errorf("%s = %v, want %s", k, md[k], v)
		}
	}
}

func TestTokenClientCredentials(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"c"}, "client_secret": {"s"}, "scope": {srv.URL + "/.default"}}
	code, b := do(t, http.MethodPost, srv.URL+"/tenant-1/oauth2/v2.0/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, b)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "mock."+srv.URL+"/.default" || tok.TokenType != "Bearer" || tok.ExpiresIn <= 0 {
		t.Fatalf("token = %+v", tok)
	}
	form.Set("grant_type", "password")
	if code, _ := do(t, http.MethodPost, srv.URL+"/tenant-1/oauth2/v2.0/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"); code != http.StatusBadRequest {
		t.Fatalf("wrong grant_type status = %d", code)
	}
}

func TestTokenChecksConfiguredSecret(t *testing.T) {
	srv, _ := newTestMock(t, Options{ClientSecret: "right"})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"c"}, "client_secret": {"wrong"}, "scope": {srv.URL + "/.default"}}
	if code, _ := do(t, http.MethodPost, srv.URL+"/t/oauth2/v2.0/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret status = %d", code)
	}
}

func TestDiscoveryRequiresGraphScope(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	graph, intune := "mock."+srv.URL+"/.default", "mock.https://api.manage.microsoft.com/.default"
	path := srv.URL + "/v1.0/servicePrincipals/appId=" + intuneAppID + "/endpoints"
	code, b := do(t, http.MethodGet, path, graph, nil, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	var disc struct {
		Value []struct {
			ProviderName string `json:"providerName"`
			URI          string `json:"uri"`
		} `json:"value"`
	}
	if err := json.Unmarshal(b, &disc); err != nil {
		t.Fatal(err)
	}
	if len(disc.Value) != 1 || disc.Value[0].ProviderName != "ScepRequestValidationFEService" || disc.Value[0].URI != srv.URL+"/intune" {
		t.Fatalf("discovery = %s", b)
	}
	if code, _ := do(t, http.MethodGet, path, intune, nil, ""); code != http.StatusUnauthorized {
		t.Errorf("intune-scoped token on discovery = %d, want 401", code)
	}
	if code, _ := do(t, http.MethodGet, srv.URL+"/v1.0/servicePrincipals/appId=other/endpoints", graph, nil, ""); code != http.StatusNotFound {
		t.Errorf("other app id = %d, want 404", code)
	}
}

func validateBody(t *testing.T, txn string, csr []byte) io.Reader {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"request": map[string]any{"transactionId": txn, "certificateRequest": csr, "callerInfo": "test"}})
	return bytes.NewReader(b)
}

func TestValidateOutcomes(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	intune := "mock.https://api.manage.microsoft.com/.default"
	u := srv.URL + "/intune/ScepActions/validateRequest"
	for _, tc := range []struct {
		challenge string
		status    int
		code      string
	}{
		{"ok-1", http.StatusOK, "Success"},
		{"reject-1", http.StatusOK, "ChallengeDecryptionError"},
		{"error-1", http.StatusServiceUnavailable, ""},
		{"", http.StatusOK, "ChallengeDecodingError"}, // no challenge: rejected, as Intune would
	} {
		t.Run("challenge="+tc.challenge, func(t *testing.T) {
			status, b := do(t, http.MethodPost, u, intune, validateBody(t, "txn", csrWithChallenge(t, tc.challenge)), "application/json")
			if status != tc.status {
				t.Fatalf("status = %d: %s", status, b)
			}
			if tc.code == "" {
				return
			}
			var cr struct {
				Code             string `json:"code"`
				ErrorDescription string `json:"errorDescription"`
			}
			if err := json.Unmarshal(b, &cr); err != nil {
				t.Fatal(err)
			}
			if cr.Code != tc.code {
				t.Fatalf("code = %q, want %q", cr.Code, tc.code)
			}
			if tc.code != "Success" && cr.ErrorDescription == "" {
				t.Error("rejection without errorDescription")
			}
		})
	}
	graph := "mock." + srv.URL + "/.default"
	if status, _ := do(t, http.MethodPost, u, graph, validateBody(t, "txn", csrWithChallenge(t, "ok-2")), "application/json"); status != http.StatusUnauthorized {
		t.Errorf("graph-scoped token on validate = %d, want 401", status)
	}
}

func TestNotificationsRecorded(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	intune := "mock.https://api.manage.microsoft.com/.default"
	post := func(path, body string) {
		t.Helper()
		status, b := do(t, http.MethodPost, srv.URL+"/intune/ScepActions/"+path, intune, strings.NewReader(body), "application/json")
		if status != http.StatusOK || !strings.Contains(string(b), `"Success"`) {
			t.Fatalf("%s: %d %s", path, status, b)
		}
	}
	post("successNotification", `{"notification":{"transactionId":"t1","certificateThumbprint":"ABCDEF"}}`)
	post("failureNotification", `{"notification":{"transactionId":"t2","hResult":-2147024809,"errorDescription":"x"}}`)

	_, b := do(t, http.MethodGet, srv.URL+"/_mock/requests", "", nil, "")
	var recs []Record
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0] != (Record{Kind: "success", TransactionID: "t1", Thumbprint: "ABCDEF"}) || recs[1].Kind != "failure" || recs[1].TransactionID != "t2" {
		t.Fatalf("records = %+v", recs)
	}
	if code, _ := do(t, http.MethodDelete, srv.URL+"/_mock/requests", "", nil, ""); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	_, b = do(t, http.MethodGet, srv.URL+"/_mock/requests", "", nil, "")
	if strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("after reset = %s", b)
	}
}

// MSAL adds the OIDC scopes to every token request; like Entra, the mock
// issues the token for the resource scope alone.
func TestTokenIgnoresOIDCScopes(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"c"}, "client_secret": {"s"},
		"scope": {srv.URL + "/.default openid offline_access profile"},
	}
	_, b := do(t, http.MethodPost, srv.URL+"/t/oauth2/v2.0/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "mock."+srv.URL+"/.default" {
		t.Fatalf("access_token = %q", tok.AccessToken)
	}
}

func tokenRequest(t *testing.T, srv string, form url.Values) (int, []byte) {
	t.Helper()
	return do(t, http.MethodPost, srv+"/t/oauth2/v2.0/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
}

// Like Entra (AADSTS500011), the mock refuses a token for a resource it doesn't
// serve, so a wrong graph_url/resource_url fails at sign-in.
func TestTokenOnlyForConfiguredScopes(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	base := url.Values{"grant_type": {"client_credentials"}, "client_id": {"c"}, "client_secret": {"s"}}
	for scope, want := range map[string]int{
		srv.URL + "/.default":                       http.StatusOK,
		"https://api.manage.microsoft.com/.default": http.StatusOK,
		"https://wrong.example/.default":            http.StatusBadRequest,
	} {
		form := url.Values{}
		for k, v := range base {
			form[k] = v
		}
		form.Set("scope", scope)
		code, b := tokenRequest(t, srv.URL, form)
		if code != want {
			t.Errorf("scope %s: status %d, want %d (%s)", scope, code, want, b)
		}
		if want == http.StatusBadRequest && !strings.Contains(string(b), "invalid_resource") {
			t.Errorf("scope %s: body %s, want invalid_resource", scope, b)
		}
	}
}

func TestTokenChecksConfiguredClientID(t *testing.T) {
	srv, _ := newTestMock(t, Options{ClientID: "right"})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"wrong"}, "client_secret": {"s"}, "scope": {srv.URL + "/.default"}}
	if code, _ := tokenRequest(t, srv.URL, form); code != http.StatusUnauthorized {
		t.Fatalf("wrong client_id status = %d", code)
	}
	form.Set("client_id", "right")
	if code, b := tokenRequest(t, srv.URL, form); code != http.StatusOK {
		t.Fatalf("right client_id status = %d: %s", code, b)
	}
}

func TestValidateBaseURL(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://intune-mock:8443":  true,
		"https://intune-mock:8443/": true,
		"intune-mock:8443":          false,
		"http://intune-mock:8443":   false,
		"https://":                  false,
		"":                          false,
	} {
		if err := ValidateBaseURL(in); (err == nil) != ok {
			t.Errorf("ValidateBaseURL(%q) = %v, want ok=%v", in, err, ok)
		}
	}
}

func TestRequestBodyLimit(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	big := strings.NewReader(`{"request":{"transactionId":"` + strings.Repeat("x", maxBodyBytes+1) + `"}}`)
	code, _ := do(t, http.MethodPost, srv.URL+"/intune/ScepActions/validateRequest", "mock.https://api.manage.microsoft.com/.default", big, "application/json")
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", code)
	}
}

func TestRecordsCapped(t *testing.T) {
	srv, m := newTestMock(t, Options{MaxRecords: 3})
	for i := range 5 {
		body := `{"notification":{"transactionId":"t` + string(rune('0'+i)) + `"}}`
		do(t, http.MethodPost, srv.URL+"/intune/ScepActions/successNotification", "mock.https://api.manage.microsoft.com/.default", strings.NewReader(body), "application/json")
	}
	recs := m.Records()
	if len(recs) != 3 || recs[0].TransactionID != "t2" || recs[2].TransactionID != "t4" {
		t.Fatalf("records = %+v, want the last 3 (t2..t4)", recs)
	}
}
