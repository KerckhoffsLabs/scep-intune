package intunemock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestMock starts the mock on an httptest server whose URL is its BaseURL.
func newTestMock(t *testing.T, opts Options) (*httptest.Server, *Mock) {
	t.Helper()
	var m *Mock
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	opts.BaseURL = srv.URL
	m = New(opts)
	return srv, m
}

// csrWithChallenge returns a DER PKCS#10 whose attributes carry challenge as a
// challengePassword (PrintableString), or no attributes when challenge is "".
// Go's x509 package can't emit challengePassword, so the request info is
// built by hand and signed with a throwaway key.
func csrWithChallenge(t testing.TB, challenge string) []byte {
	t.Helper()
	return csrWithChallengeEncoding(t, challenge, "printable")
}

// csrWithChallengeEncoding is csrWithChallenge with the challenge encoded as
// the given asn1 string type ("printable" or "utf8").
func csrWithChallengeEncoding(t testing.TB, challenge, encoding string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Let x509 produce a valid CSR, then lift its subject and public key.
	base, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Info   asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(base, &outer); err != nil {
		t.Fatal(err)
	}
	var info struct {
		Version int
		Subject asn1.RawValue
		PKI     asn1.RawValue
		Attrs   asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		t.Fatal(err)
	}
	attrs := []byte{}
	if challenge != "" {
		val, _ := asn1.MarshalWithParams(challenge, encoding)
		attr, err := asn1.Marshal(struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}{oidChallengePassword, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: val}})
		if err != nil {
			t.Fatal(err)
		}
		attrs = attr
	}
	newInfo, err := asn1.Marshal(struct {
		Version int
		Subject asn1.RawValue
		PKI     asn1.RawValue
		Attrs   asn1.RawValue
	}{info.Version, info.Subject, info.PKI, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs}})
	if err != nil {
		t.Fatal(err)
	}
	// The mock never verifies the signature; reuse the original one.
	der, err := asn1.Marshal(struct {
		Info   asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: newInfo}, outer.SigAlg, outer.Sig})
	if err != nil {
		t.Fatal(err)
	}
	return der
}
