package mssql

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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
	if params.fedAuthLibrary == fedAuthLibraryReserved {
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

func getFedAuthClientCertificate(clientCertPath, clientCertPassword string) (certificate *x509.Certificate, privateKey *rsa.PrivateKey, err error) {
	pemBytes, err := ioutil.ReadFile(clientCertPath)
	if err != nil {
	}

	var block, encryptedPrivateKey *pem.Block
	var certificateBytes, privateKeyBytes []byte

	for block, pemBytes = pem.Decode(pemBytes); block != nil; block, pemBytes = pem.Decode(pemBytes) {
		_, dekInfo := block.Headers["DEK-Info"]
		switch {
		case block.Type == "CERTIFICATE":
			certificateBytes = block.Bytes
		case block.Type == "RSA PRIVATE KEY" && dekInfo:
			encryptedPrivateKey = block
		case block.Type == "RSA PRIVATE KEY":
			privateKeyBytes = block.Bytes
		default:
			return nil, nil, fmt.Errorf("PEM file %s contains unsupported block type %s", clientCertPath, block.Type)
		}
	}

	if len(certificateBytes) == 0 {
		return nil, nil, fmt.Errorf("No certificate found in PEM file at path %s: %v", clientCertPath, err)
	}

	certificate, err = x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse certificate found in PEM file at path %s: %v", clientCertPath, err)
	}

	if encryptedPrivateKey != nil {
		privateKeyBytes, err = x509.DecryptPEMBlock(encryptedPrivateKey, []byte(clientCertPassword))
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to decrypt private key found in PEM file at path %s: %v", clientCertPath, err)
		}
	}

	if len(privateKeyBytes) == 0 {
		return nil, nil, fmt.Errorf("No private key found in PEM file at path %s: %v", clientCertPath, err)
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse private key found in PEM file at path %s: %v", clientCertPath, err)
	}

	return
}
