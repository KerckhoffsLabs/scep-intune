package intune

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		Raw:          []byte("hello-der"),
		SerialNumber: big.NewInt(255),
		NotAfter:     time.Date(2027, 3, 4, 5, 6, 7, 123_000_000, time.UTC),
		Issuer:       pkix.Name{CommonName: "Step Intermediate CA"},
	}
}

func TestThumbprintSHA1(t *testing.T) {
	got := thumbprintSHA1(testCert(t))
	want := "2E:69:C9:CE:84:06:4E:03:83:C9:57:28:07:1B:6A:3D:E1:A1:1E:EE"
	if got != want {
		t.Fatalf("thumbprint = %q want %q", got, want)
	}
}

func TestExpiryFormatHasMillis(t *testing.T) {
	got := expiryUTC(testCert(t))
	want := "2027-03-04T05:06:07.123Z"
	if got != want {
		t.Fatalf("expiry = %q want %q", got, want)
	}
}

func TestSerialDecimal(t *testing.T) {
	if got := serialNumber(testCert(t)); got != "255" {
		t.Fatalf("serial = %q", got)
	}
}
