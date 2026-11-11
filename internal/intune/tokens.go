package intune

import (
	"context"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// EntraTokens acquires tokens via the Entra ID client-credentials flow.
type EntraTokens struct {
	cred *azidentity.ClientSecretCredential
}

// Compile-time check: EntraTokens must satisfy the tokenSource interface.
var _ tokenSource = (*EntraTokens)(nil)

// NewEntraTokens builds a tokenSource from an Entra app registration.
// authorityHost is the Entra sign-in host; empty or the commercial-cloud host
// keeps the Azure SDK defaults.
func NewEntraTokens(tenantID, clientID, clientSecret, authorityHost string) (*EntraTokens, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret,
		credentialOptions(authorityHost, os.Getenv(azureAuthorityHostEnv)))
	if err != nil {
		return nil, err
	}
	return &EntraTokens{cred: cred}, nil
}

// Token returns an access token for scope from Entra ID.
func (e *EntraTokens) Token(ctx context.Context, scope string) (string, error) {
	tk, err := e.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", err
	}
	return tk.Token, nil
}

// azureAuthorityHostEnv is the variable the Azure SDK reads for its default
// authority when the credential options leave the cloud unset.
const azureAuthorityHostEnv = "AZURE_AUTHORITY_HOST"

// sameHost compares two authority URLs ignoring case and a trailing slash.
func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// EnvAuthorityConflicts reports whether AZURE_AUTHORITY_HOST (env) is set to a
// host other than the configured authority. The bridge's configuration wins in
// that case; callers should warn so the override is not silent.
func EnvAuthorityConflicts(configured, env string) bool {
	return env != "" && !sameHost(configured, env)
}

// KnownMicrosoftAuthority reports whether host is one of the Entra authorities
// the Azure SDK knows (commercial, US Government, China). Any other host, such
// as a test mock, receives the bridge's real client secret, so callers should
// say so loudly.
func KnownMicrosoftAuthority(host string) bool {
	for _, c := range []cloud.Configuration{cloud.AzurePublic, cloud.AzureGovernment, cloud.AzureChina} {
		if sameHost(host, c.ActiveDirectoryAuthorityHost) {
			return true
		}
	}
	return false
}

// credentialOptions returns nil (the SDK defaults, exactly as before endpoints
// were configurable) for an empty or commercial-cloud authority host, unless
// AZURE_AUTHORITY_HOST would make the SDK use another host: then the options
// pin the commercial host, with instance discovery still on, so the bridge's
// configuration stays the single source of truth.
//
// For any other host they point the SDK there and disable instance discovery,
// which would otherwise ask login.microsoftonline.com to approve the unknown
// host: impossible for a mock and unwanted for a national cloud's own host.
func credentialOptions(authorityHost, envAuthorityHost string) *azidentity.ClientSecretCredentialOptions {
	public := cloud.AzurePublic.ActiveDirectoryAuthorityHost
	if authorityHost == "" || sameHost(authorityHost, public) {
		if !EnvAuthorityConflicts(public, envAuthorityHost) {
			return nil
		}
		return &azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{Cloud: cloud.AzurePublic},
		}
	}
	return &azidentity.ClientSecretCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloud.Configuration{ActiveDirectoryAuthorityHost: authorityHost},
		},
		DisableInstanceDiscovery: true,
	}
}
