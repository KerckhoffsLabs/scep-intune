package intune

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"strings"
)

// thumbprintSHA1 returns the uppercase, colon-separated SHA-1 of the cert DER.
func thumbprintSHA1(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// expiryUTC formats NotAfter as ISO-8601 UTC with milliseconds, per the Intune
// spec (YYYY-MM-DDThh:mm:ss.sssTZD).
func expiryUTC(cert *x509.Certificate) string {
	return cert.NotAfter.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

func serialNumber(cert *x509.Certificate) string {
	return cert.SerialNumber.String()
}
