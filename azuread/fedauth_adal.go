package azuread

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/Azure/go-autorest/autorest/adal"
	mssql "github.com/denisenkom/go-mssqldb"
)

type azureFedAuthConfigurer struct{}

func init() {
	mssql.SetFederatedAuthenticationConfigurer(&azureFedAuthConfigurer{})
}

// When the security token library is used, the token is obtained without input
// from the server, so the AD endpoint and Azure SQL resource URI are provided
// from the constants below.
const (
	// activeDirectoryEndpoint is the security token service URL to use when
	// the server does not provide the URL.
	activeDirectoryEndpoint = "https://login.microsoftonline.com/"

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

func (az *azureFedAuthConfigurer) SecurityTokenProviderFromCertificate(clientID, tenantID string, certificate *x509.Certificate, rsaPrivateKey *rsa.PrivateKey) mssql.SecurityTokenProvider {
	return func(ctx context.Context) (string, error) {
		// The activeDirectoryEndpoint URL is used as a base against which the
		// tenant ID is resolved.
		oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, tenantID)
		if err != nil {
			err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
				activeDirectoryEndpoint, tenantID, err)
			return "", err
		}

		token, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, clientID, certificate, rsaPrivateKey, azureSQLResource)
		if err != nil {
			err = fmt.Errorf("Failed to obtain service principal token for client id %s in tenant %s: %v", clientID, tenantID, err)
			return "", err
		}

		return retrieveToken(ctx, token)
	}
}

func (az *azureFedAuthConfigurer) SecurityTokenProviderFromSecret(clientID, tenantID, clientSecret string) mssql.SecurityTokenProvider {
	return func(ctx context.Context) (string, error) {
		// The activeDirectoryEndpoint URL is used as a base against which the
		// tenant ID is resolved.
		oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, tenantID)
		if err != nil {
			err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
				activeDirectoryEndpoint, tenantID, err)
			return "", err
		}

		token, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, azureSQLResource)

		if err != nil {
			err = fmt.Errorf("Failed to obtain service principal token for client id %s in tenant %s: %v", clientID, tenantID, err)
			return "", err
		}

		return retrieveToken(ctx, token)
	}
}

func (az *azureFedAuthConfigurer) ActiveDirectoryTokenProviderFromPassword(user, password string) mssql.ActiveDirectoryTokenProvider {
	return func(ctx context.Context, serverSPN, stsURL string) (string, error) {
		// The activeDirectoryEndpoint URL is used as a base against which the
		// STS URL is resolved. However, the STS URL is normally absolute and
		// the activeDirectoryEndpoint URL is completely ignored.
		oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, stsURL)
		if err != nil {
			err = fmt.Errorf("Failed to obtain OAuth configuration for endpoint %s and tenant %s: %v",
				activeDirectoryEndpoint, stsURL, err)
			return "", err
		}

		token, err := adal.NewServicePrincipalTokenFromUsernamePassword(*oauthConfig, driverClientID, user, password, serverSPN)

		if err != nil {
			err = fmt.Errorf("Failed to obtain token for user %s for resource %s from service %s: %v", user, serverSPN, stsURL, err)
			return "", err
		}

		return retrieveToken(ctx, token)
	}
}

func (az *azureFedAuthConfigurer) ActiveDirectoryTokenProviderFromIdentity(clientID string) mssql.ActiveDirectoryTokenProvider {
	return func(ctx context.Context, serverSPN, stsURL string) (string, error) {
		msiEndpoint, err := adal.GetMSIEndpoint()
		if err != nil {
			return "", err
		}

		var token *adal.ServicePrincipalToken
		var access string
		if clientID == "" {
			access = "system identity"
			token, err = adal.NewServicePrincipalTokenFromMSI(msiEndpoint, serverSPN)
		} else {
			access = "user-assigned identity " + clientID
			token, err = adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, serverSPN, clientID)
		}

		if err != nil {
			err = fmt.Errorf("Failed to obtain token for %s for resource %s from service %s: %v", access, serverSPN, stsURL, err)
			return "", err
		}

		return retrieveToken(ctx, token)
	}
}
