package intune

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeTokens struct{}

func (fakeTokens) Token(_ context.Context, _ string) (string, error) { return "tok", nil }

// newTestServer serves both the Graph discovery endpoint and the ScepActions
// endpoints, recording the last validate/notify bodies.
func newTestServer(t *testing.T, validateCode string) (*httptest.Server, *[]byte) {
	t.Helper()
	var lastBody []byte
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, r *http.Request) {
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
		w.WriteHeader(200)
	})
	mux.HandleFunc("/"+pathNotifyFailure, func(w http.ResponseWriter, r *http.Request) {
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

func newTestClient(srv *httptest.Server) *Client {
	c := New(fakeTokens{}, "scep-step-ca/test")
	c.http = srv.Client()
	c.graphBaseURL = srv.URL + "/" // override Graph base to the test server
	return c
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
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{
			{ProviderName: validationServiceName, URI: srv.URL},
		}})
	})
	mux.HandleFunc("/"+pathNotifyFailure, func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/v1.0/servicePrincipals/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse{Value: []endpoint{
			{ProviderName: validationServiceName, URI: srv.URL},
		}})
	})
	mux.HandleFunc("/"+pathValidate, func(w http.ResponseWriter, r *http.Request) {
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
