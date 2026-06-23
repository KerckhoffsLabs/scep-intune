package intune

import (
	"context"

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
func NewEntraTokens(tenantID, clientID, clientSecret string) (*EntraTokens, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}
	return &EntraTokens{cred: cred}, nil
}

func (e *EntraTokens) Token(ctx context.Context, scope string) (string, error) {
	tk, err := e.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", err
	}
	return tk.Token, nil
}
