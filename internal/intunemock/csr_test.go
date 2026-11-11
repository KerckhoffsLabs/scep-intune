package intunemock

import (
	"strings"
	"testing"
)

func TestChallengeFromCSR(t *testing.T) {
	valid := csrWithChallenge(t, "ok-1")
	for _, tc := range []struct {
		name    string
		der     []byte
		want    string
		wantErr bool
	}{
		{name: "printable challenge", der: valid, want: "ok-1"},
		{name: "utf8 challenge", der: csrWithChallengeEncoding(t, "ok-é", "utf8"), want: "ok-é"},
		{name: "no attributes", der: csrWithChallenge(t, ""), want: ""},
		{name: "empty input", der: nil, wantErr: true},
		{name: "truncated", der: valid[:len(valid)/2], wantErr: true},
		{name: "trailing garbage", der: append(append([]byte{}, valid...), 0x00, 0x01), wantErr: true},
		{name: "not DER", der: []byte("not a csr"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := challengeFromCSR(tc.der)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("challenge = %q, want %q", got, tc.want)
			}
		})
	}
}

// A malformed CSR gets a rejection code, not a 5xx, so the bridge answers
// allow:false instead of making step-ca retry.
func TestValidateMalformedCSR(t *testing.T) {
	srv, _ := newTestMock(t, Options{})
	status, b := do(t, "POST", srv.URL+"/intune/ScepActions/validateRequest", "mock.https://api.manage.microsoft.com/.default",
		validateBody(t, "txn", []byte("not a csr")), "application/json")
	if status != 200 || !strings.Contains(string(b), `"CsrParsingError"`) {
		t.Fatalf("status %d body %s", status, b)
	}
}

// FuzzChallengeFromCSR checks the parser never panics on arbitrary input. Run
// longer with: go test ./internal/intunemock -run '^$' -fuzz FuzzChallengeFromCSR
func FuzzChallengeFromCSR(f *testing.F) {
	for _, seed := range [][]byte{
		csrWithChallenge(f, "ok-1"),
		csrWithChallengeEncoding(f, "ok-é", "utf8"),
		csrWithChallenge(f, ""),
		nil,
		[]byte("not a csr"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, der []byte) {
		_, _ = challengeFromCSR(der)
	})
}
