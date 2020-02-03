package mssql

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/pkcs12"
)

// FederatedAuthenticationConfigurer implementations use the connection string
// parameters to create a token provider that can be used to obtain tokens
// during the login sequence.
type FederatedAuthenticationConfigurer interface {
	SecurityTokenProviderFromCertificate(clientID, tenantID string, cert *x509.Certificate, key *rsa.PrivateKey) SecurityTokenProvider
	SecurityTokenProviderFromSecret(clientID, tenantID, clientSecret string) SecurityTokenProvider
	ActiveDirectoryTokenProviderFromPassword(user, password string) ActiveDirectoryTokenProvider
	ActiveDirectoryTokenProviderFromIdentity(clientID string) ActiveDirectoryTokenProvider
}

// SetFederatedAuthenticationConfigurer injects an implementation to use.
func SetFederatedAuthenticationConfigurer(library FederatedAuthenticationConfigurer) {
	fedAuthConfigurer = library
}

var fedAuthConfigurer FederatedAuthenticationConfigurer

func (c *Connector) checkFedAuthProviders(params *connectParams) error {
	// If there is a user-specified SecurityTokenProvider, use that in preference
	// to DSN or ActiveDirectoryTokenProvider.
	if c != nil && c.SecurityTokenProvider != nil {
		params.fedAuthLibrary = fedAuthLibrarySecurityToken
		params.securityTokenProvider = c.SecurityTokenProvider

		return nil
	}

	// Likewise if there is an existing user-specified ActiveDirectoryTokenProvider.
	if c != nil && c.ActiveDirectoryTokenProvider != nil {
		params.fedAuthLibrary = fedAuthLibraryADAL
		params.activeDirectoryTokenProvider = c.ActiveDirectoryTokenProvider

		return nil
	}

	// Ignore DSNs that don't request one of the supported federated authentication
	// libraries.
	if params.fedAuthLibrary != fedAuthLibrarySecurityToken && params.fedAuthLibrary != fedAuthLibraryADAL {
		return nil
	}

	if fedAuthConfigurer == nil {
		return errors.New("No federated authentication library available: inject using SetFederatedAuthenticationConfigurer")
	}

	switch {
	case params.fedAuthLibrary == fedAuthLibrarySecurityToken && params.aadClientCertPath != "":
		certificate, rsaPrivateKey, err := getFedAuthClientCertificate(params.aadClientCertPath, params.password)
		if err != nil {
			return err
		}

		params.securityTokenProvider = fedAuthConfigurer.SecurityTokenProviderFromCertificate(params.user, params.aadTenantID, certificate, rsaPrivateKey)

	case params.fedAuthLibrary == fedAuthLibrarySecurityToken:
		params.securityTokenProvider = fedAuthConfigurer.SecurityTokenProviderFromSecret(params.user, params.aadTenantID, params.password)

	case params.fedAuthLibrary == fedAuthLibraryADAL && params.fedAuthADALWorkflow == fedAuthADALWorkflowPassword:
		params.activeDirectoryTokenProvider = fedAuthConfigurer.ActiveDirectoryTokenProviderFromPassword(params.user, params.password)

	case params.fedAuthLibrary == fedAuthLibraryADAL && params.fedAuthADALWorkflow == fedAuthADALWorkflowMSI:
		params.activeDirectoryTokenProvider = fedAuthConfigurer.ActiveDirectoryTokenProviderFromIdentity(params.user)

	case params.fedAuthLibrary == fedAuthLibraryADAL:
		return errors.New("Unsupported ADAL workflow")

	default:
		return errors.New("Unsupported federated authentication library")
	}

	return nil
}

func getFedAuthClientCertificate(clientCertPath, clientCertPassword string) (*x509.Certificate, *rsa.PrivateKey, error) {
	pkcs, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read the AD client certificate from path %s: %v", clientCertPath, err)
	}

	privateKey, certificate, err := pkcs12.Decode(pkcs, clientCertPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read the AD client certificate from path %s: %v", clientCertPath, err)
	}

	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
		return nil, nil, fmt.Errorf("AD client certificate at path %s must contain an RSA private key", clientCertPath)
	}

	return certificate, rsaPrivateKey, nil
}
