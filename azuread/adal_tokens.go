package azuread

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Azure/go-autorest/autorest/adal"
)

// When the security token library is used, the token is obtained without input
// from the server, so the AD endpoint and Azure SQL resource URI are provided
// from the constants below.
var (
	// activeDirectoryEndpoint is the security token service URL to use when
	// the server does not provide the URL.
	activeDirectoryEndpoint = "https://login.microsoftonline.com/"
)

func init() {
	endpoint := os.Getenv("AZURE_AD_STS_URL")
	if endpoint != "" {
		activeDirectoryEndpoint = endpoint
	}
}

const (
	// azureSQLResource is the AD resource to use when the server does not
	// provide the resource.
	azureSQLResource = "https://database.windows.net/"

	// driverClientID is the AD client ID to use when performing a username
	// and password login.
	driverClientID = "7f98cb04-cd1e-40df-9140-3bf7e2cea4db"
)

func retrieveToken(ctx context.Context, token *adal.ServicePrincipalToken) (string, error) {
	err := token.RefreshWithContext(ctx)
	if err != nil {
		err = fmt.Errorf("Failed to refresh token: %v", err)
		return "", err
	}

	return token.Token().AccessToken, nil
}

func (p *azureFedAuthProvider) ProvideSecurityToken(ctx context.Context) (string, error) {
	switch {
	case p.certificate != nil && p.privateKey != nil:
		return p.securityTokenFromCertificate(ctx)
	case p.clientSecret != "":
		return p.securityTokenFromSecret(ctx)
	}

	return "", errors.New("Client certificate and key, or client secret, required for service principal login")
}

func (p *azureFedAuthProvider) securityTokenFromCertificate(ctx context.Context) (string, error) {
	// The activeDirectoryEndpoint URL is used as a base against which the
	// tenant ID is resolved.
	oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, p.tenantID)
	if err != nil {
		err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
			activeDirectoryEndpoint, p.tenantID, err)
		return "", err
	}

	token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, p.clientID, p.certificate, p.privateKey, azureSQLResource)
	if err != nil {
		err = fmt.Errorf("Failed to obtain service principal token for client id %s in tenant %s: %v", p.clientID, p.tenantID, err)
		return "", err
	}

	return retrieveToken(ctx, token)
}

func (p *azureFedAuthProvider) securityTokenFromSecret(ctx context.Context) (string, error) {
	// The activeDirectoryEndpoint URL is used as a base against which the
	// tenant ID is resolved.
	oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, p.tenantID)
	if err != nil {
		err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
			activeDirectoryEndpoint, p.tenantID, err)
		return "", err
	}

	token, err := adal.NewServicePrincipalToken(*oauthConfig, p.clientID, p.clientSecret, azureSQLResource)

	if err != nil {
		err = fmt.Errorf("Failed to obtain service principal token for client id %s in tenant %s: %v", p.clientID, p.tenantID, err)
		return "", err
	}

	return retrieveToken(ctx, token)
}

func (p *azureFedAuthProvider) ProvideActiveDirectoryToken(ctx context.Context, serverSPN, stsURL string) (string, error) {
	switch p.adalWorkflow {
	case fedAuthADALWorkflowPassword:
		return p.activeDirectoryTokenFromPassword(ctx, serverSPN, stsURL)
	case fedAuthADALWorkflowMSI:
		return p.activeDirectoryTokenFromIdentity(ctx, serverSPN, stsURL)
	}

	return "", fmt.Errorf("ADAL workflow id %d not supported", p.adalWorkflow)
}

func (p *azureFedAuthProvider) activeDirectoryTokenFromPassword(ctx context.Context, serverSPN, stsURL string) (string, error) {
	// The activeDirectoryEndpoint URL is used as a base against which the
	// STS URL is resolved. However, the STS URL is normally absolute and
	// the activeDirectoryEndpoint URL is completely ignored.
	oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, stsURL)
	if err != nil {
		err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
			activeDirectoryEndpoint, stsURL, err)
		return "", err
	}

	token, err := adal.NewServicePrincipalTokenFromUsernamePassword(*oauthConfig, driverClientID, p.user, p.password, serverSPN)

	if err != nil {
		err = fmt.Errorf("Failed to obtain token for user %s for resource %s from service %s: %v", p.user, serverSPN, stsURL, err)
		return "", err
	}

	return retrieveToken(ctx, token)
}

func (p *azureFedAuthProvider) activeDirectoryTokenFromIdentity(ctx context.Context, serverSPN, stsURL string) (string, error) {
	msiEndpoint, err := adal.GetMSIEndpoint()
	if err != nil {
		return "", err
	}

	var token *adal.ServicePrincipalToken
	var access string
	if p.clientID == "" {
		access = "system identity"
		token, err = adal.NewServicePrincipalTokenFromMSI(msiEndpoint, serverSPN)
	} else {
		access = "user-assigned identity " + p.clientID
		token, err = adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, serverSPN, p.clientID)
	}

	if err != nil {
		err = fmt.Errorf("Failed to obtain token for %s for resource %s from service %s: %v", access, serverSPN, stsURL, err)
		return "", err
	}

	return retrieveToken(ctx, token)
}
