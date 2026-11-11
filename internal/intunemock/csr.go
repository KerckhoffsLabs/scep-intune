package intunemock

import (
	"encoding/asn1"
	"errors"
)

// oidChallengePassword is PKCS#9 challengePassword (1.2.840.113549.1.9.7),
// the CSR attribute in which SCEP clients carry the enrollment challenge.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

type csrAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// challengeFromCSR returns the challengePassword of a DER PKCS#10 request, or
// "" when it has none. The signature is not verified: the mock only needs the
// challenge. Go's x509.CertificateRequest.Attributes is deprecated and can't
// represent this attribute, hence the manual parse.
func challengeFromCSR(der []byte) (string, error) {
	var outer struct {
		Info   asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) > 0 {
		return "", errors.New("intunemock: malformed CSR")
	}
	var info struct {
		Version int
		Subject asn1.RawValue
		PKI     asn1.RawValue
		Attrs   asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(outer.Info.FullBytes, &info); err != nil {
		return "", errors.New("intunemock: malformed CSR info")
	}
	rest := info.Attrs.Bytes
	for len(rest) > 0 {
		var attr csrAttribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &attr); err != nil {
			return "", errors.New("intunemock: malformed CSR attribute")
		}
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		var val asn1.RawValue // PrintableString, UTF8String, ... : take the bytes
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &val); err != nil {
			return "", errors.New("intunemock: malformed challengePassword")
		}
		return string(val.Bytes), nil
	}
	return "", nil
}
