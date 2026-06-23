// Package intune validates SCEP requests against Microsoft Intune and reports
// certificate issuance results back to it.
package intune

const (
	apiVersion            = "2018-02-20"
	graphAPIVersion       = "1.0"
	validationServiceName = "ScepRequestValidationFEService"
	intuneAppID           = "0000000a-0000-0000-c000-000000000000"

	graphBaseURL = "https://graph.microsoft.com/"
	graphScope   = "https://graph.microsoft.com/.default"
	intuneScope  = "https://api.manage.microsoft.com/.default"

	pathValidate      = "ScepActions/validateRequest"
	pathNotifySuccess = "ScepActions/successNotification"
	pathNotifyFailure = "ScepActions/failureNotification"
)

// reqInfo is the body of validateRequest. certificateRequest is the raw DER
// PKCS#10; encoding/json marshals []byte as standard base64, which is the
// "Base 64 encoded PKCS10 packet" the API expects.
type reqInfo struct {
	TransactionID      string `json:"transactionId"`
	CertificateRequest []byte `json:"certificateRequest"`
	CallerInfo         string `json:"callerInfo"`
}

type validateBody struct {
	Request reqInfo `json:"request"`
}

type notifyInfo struct {
	TransactionID                string `json:"transactionId,omitempty"`
	CertificateRequest           []byte `json:"certificateRequest,omitempty"`
	CertificateThumbprint        string `json:"certificateThumbprint,omitempty"`
	CertificateSerialNumber      string `json:"certificateSerialNumber,omitempty"`
	CertificateExpirationDateUtc string `json:"certificateExpirationDateUtc,omitempty"`
	IssuingCertificateAuthority  string `json:"issuingCertificateAuthority,omitempty"`
	HResult                      int32  `json:"hResult,omitempty"`
	ErrorDescription             string `json:"errorDescription,omitempty"`
	CallerInfo                   string `json:"callerInfo,omitempty"`
}

type notifyBody struct {
	Notification notifyInfo `json:"notification"`
}

// codeResponse is the validateRequest reply.
type codeResponse struct {
	Code             string `json:"code"`
	ErrorDescription string `json:"errorDescription"`
}

type endpoint struct {
	ProviderName string `json:"providerName"`
	URI          string `json:"uri"`
}

type discoveryResponse struct {
	Value []endpoint `json:"value"`
}
