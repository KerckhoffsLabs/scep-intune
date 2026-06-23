package intune

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"strings"
)

// thumbprintSHA1 returns the uppercase, colon-separated SHA-1 of the cert DER.
//
// SHA-1 here is not a security-sensitive use: the SHA-1 certificate thumbprint
// is the X.509 fingerprint identifier mandated by Microsoft Intune's SCEP
// validation API (sent as certificateThumbprint). It is an identity/lookup key,
// not used for integrity, signatures, or secrets, and the algorithm is fixed by
// the upstream API contract. Hence the weak-hash finding (sonar go:S4790) is a
// false positive and is suppressed below.
func thumbprintSHA1(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw) //nosonar S4790 -- Intune-mandated cert thumbprint, not a sensitive hash
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
