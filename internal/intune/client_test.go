package intune

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakeTokens returns a fixed token and records the scopes it was asked for.
type fakeTokens struct {
	mu     sync.Mutex
	scopes []string
}

func (f *fakeTokens) Token(_ context.Context, scope string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, scope)
	return "tok", nil
}

const testResourceURL = "https://res.example/"

// newTestServer serves both the Graph discovery endpoint and the ScepActions
// endpoints, recording the last validate/notify bodies.
func newTestServer(t *testing.T, validateCode string) (*httptest.Server, *[]byte) {
	t.Helper()
	var lastBody []byte
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{
			{ProviderName: "Other", URI: "https://wrong"},
			{ProviderName: validationServiceName, URI: srv.URL},
		}})
	})
	mux.HandleFunc("/"+pathValidate, func(w http.ResponseWriter, r *http.Request) {
		lastBody, _ = io.ReadAll(r.Body)
		if r.Header.Get("Api-Version") != apiVersion {
			t.Errorf("Api-Version = %q", r.Header.Get("Api-Version"))
		}
		_ = json.NewEncoder(w).Encode(codeResponse{Code: validateCode})
	})
	mux.HandleFunc("/"+pathNotifySuccess, func(w http.ResponseWriter, r *http.Request) {
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/"+pathNotifyFailure, func(w http.ResponseWriter, r *http.Request) {
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

func newTestClient(srv *httptest.Server) *Client {
	c, _ := newRecordingClient(srv)
	return c
}

// newRecordingClient points the client's Graph base at the test server and
// returns the token source so tests can inspect the requested scopes.
func newRecordingClient(srv *httptest.Server) (*Client, *fakeTokens) {
	tok := &fakeTokens{}
	c := New(tok, "scep-step-ca/test", Endpoints{
		GraphURL:    srv.URL + "/",
		ResourceURL: testResourceURL,
		AppID:       "app-123",
	})
	c.http = srv.Client()
	return c, tok
}

func TestDiscoveryUsesAppID(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{{ProviderName: validationServiceName, URI: srv.URL}}})
	})
	mux.HandleFunc("/"+pathValidate, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(codeResponse{Code: "Success"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if err := newTestClient(srv).Validate(context.Background(), "txn", []byte("der")); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1.0/servicePrincipals/appId=app-123/endpoints" {
		t.Fatalf("discovery path = %q", gotPath)
	}
}

func TestScopesDerivedFromEndpoints(t *testing.T) {
	srv, _ := newTestServer(t, "Success")
	c, tok := newRecordingClient(srv)
	if err := c.Validate(context.Background(), "txn", []byte("der")); err != nil {
		t.Fatal(err)
	}
	want := []string{srv.URL + "/.default", testResourceURL + ".default"}
	if !reflect.DeepEqual(tok.scopes, want) {
		t.Fatalf("scopes = %v, want %v", tok.scopes, want)
	}
}

func TestValidateSuccess(t *testing.T) {
	srv, body := newTestServer(t, "Success")
	c := newTestClient(srv)
	if err := c.Validate(context.Background(), "txn-1", []byte("der")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(*body), `"transactionId":"txn-1"`) {
		t.Fatalf("body = %s", *body)
	}
	if !strings.Contains(string(*body), `"certificateRequest":"ZGVy"`) { // base64("der")
		t.Fatalf("csr not base64: %s", *body)
	}
}

func TestValidateRejected(t *testing.T) {
	srv, _ := newTestServer(t, "ChallengeExpired")
	c := newTestClient(srv)
	err := c.Validate(context.Background(), "txn-2", []byte("der"))
	if err == nil || !strings.Contains(err.Error(), "ChallengeExpired") {
		t.Fatalf("err = %v", err)
	}
}

func TestNotifySuccessBody(t *testing.T) {
	srv, body := newTestServer(t, "Success")
	c := newTestClient(srv)
	cert := testCert(t)
	if err := c.NotifySuccess(context.Background(), "txn-3", []byte("der"), cert); err != nil {
		t.Fatal(err)
	}
	s := string(*body)
	for _, want := range []string{`"transactionId":"txn-3"`, `"certificateSerialNumber":"255"`, `"certificateExpirationDateUtc":"2027-03-04T05:06:07.123Z"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
}

func TestNotifyFailureTruncates(t *testing.T) {
	srv, body := newTestServer(t, "Success")
	c := newTestClient(srv)
	long := strings.Repeat("x", 300)
	if err := c.NotifyFailure(context.Background(), "txn-4", []byte("der"), -2147467259, long); err != nil {
		t.Fatal(err)
	}
	var nb notifyBody
	if err := json.Unmarshal(*body, &nb); err != nil {
		t.Fatal(err)
	}
	if got := len(nb.Notification.ErrorDescription); got != 255 {
		t.Fatalf("errorDescription length = %d, want 255", got)
	}
}

func TestNotifyFailureNon200(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{
			{ProviderName: validationServiceName, URI: srv.URL},
		}})
	})
	mux.HandleFunc("/"+pathNotifyFailure, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestClient(srv)
	err := c.NotifyFailure(context.Background(), "txn-5", []byte("der"), -2147467259, "boom")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want HTTP 500 error", err)
	}
}

func TestValidateTransientHTTPError(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{
			{ProviderName: validationServiceName, URI: srv.URL},
		}})
	})
	mux.HandleFunc("/"+pathValidate, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503: transient, not a rejection
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := newTestClient(srv)
	err := c.Validate(context.Background(), "txn-6", []byte("der"))
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v, want transient HTTP 503 error (not a rejection)", err)
	}
}

// With an https Graph URL (always the case in production: config rejects
// anything else), the bridge must not send its Intune token to a non-https
// address returned by discovery.
func TestDiscoveryRejectsNonHTTPSServiceURI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{{ProviderName: validationServiceName, URI: "http://plaintext.example/intune"}}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	c := New(&fakeTokens{}, "test", Endpoints{GraphURL: srv.URL + "/", ResourceURL: testResourceURL, AppID: "app"})
	c.http = srv.Client()
	err := c.Validate(context.Background(), "txn", []byte("der"))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want a refusal of the non-https service URI", err)
	}
}
