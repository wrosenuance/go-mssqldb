package azuread

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	mssql "github.com/denisenkom/go-mssqldb"
)

const (
	fedAuthActiveDirectoryPassword    = "ActiveDirectoryPassword"
	fedAuthActiveDirectoryIntegrated  = "ActiveDirectoryIntegrated"
	fedAuthActiveDirectoryMSI         = "ActiveDirectoryMSI"
	fedAuthActiveDirectoryApplication = "ActiveDirectoryApplication"
)

// Federated authentication library affects the login data structure and message sequence.
const (
	// fedAuthLibraryLiveIDCompactToken specifies the Microsoft Live ID Compact Token authentication scheme
	fedAuthLibraryLiveIDCompactToken = 0x00

	// fedAuthLibrarySecurityToken specifies a token-based authentication where the token is available
	// without additional information provided during the login sequence.
	fedAuthLibrarySecurityToken = 0x01

	// fedAuthLibraryADAL specifies a token-based authentication where a token is obtained during the
	// login sequence using the server SPN and STS URL provided by the server during login.
	fedAuthLibraryADAL = 0x02

	// fedAuthLibraryReserved is used to indicate that no federated authentication scheme applies.
	fedAuthLibraryReserved = 0x7F
)

// Federated authentication ADAL workflow affects the mechanism used to authenticate.
const (
	// fedAuthADALWorkflowPassword uses a username/password to obtain a token from Active Directory
	fedAuthADALWorkflowPassword = 0x01

	// fedAuthADALWorkflowPassword uses the Windows identity to obtain a token from Active Directory
	fedAuthADALWorkflowIntegrated = 0x02

	// fedAuthADALWorkflowMSI uses the managed identity service to obtain a token
	fedAuthADALWorkflowMSI = 0x03
)

type azureFedAuthProvider struct {
	// Service principal logins
	clientID     string
	tenantID     string
	clientSecret string
	certificate  *x509.Certificate
	privateKey   *rsa.PrivateKey

	// ADAL workflows
	adalWorkflow byte
	user         string
	password     string
}

func (p *azureFedAuthProvider) ConfigureProvider(fedAuth *mssql.FederatedAuthenticationState) (err error) {
	switch {
	case strings.EqualFold(fedAuth.FedAuthWorkflow, fedAuthActiveDirectoryPassword):
		fedAuth.FedAuthLibrary = fedAuthLibraryADAL
		fedAuth.ADALWorkflow = fedAuthADALWorkflowPassword

		p.adalWorkflow = fedAuthADALWorkflowPassword
		p.user = fedAuth.UserName
		p.password = fedAuth.Password

	case strings.EqualFold(fedAuth.FedAuthWorkflow, fedAuthActiveDirectoryIntegrated):
		// Active Directory Integrated authentication is not fully supported:
		// you can only use this by also implementing an a token provider
		// and supplying it via ActiveDirectoryTokenProvider in the Connection.
		fedAuth.FedAuthLibrary = fedAuthLibraryADAL
		fedAuth.ADALWorkflow = fedAuthADALWorkflowIntegrated

		p.adalWorkflow = fedAuthADALWorkflowIntegrated

	case strings.EqualFold(fedAuth.FedAuthWorkflow, fedAuthActiveDirectoryMSI):
		// When using MSI, to request a specific client ID or user-assigned identity,
		// provide the ID as the username.
		fedAuth.FedAuthLibrary = fedAuthLibraryADAL
		fedAuth.ADALWorkflow = fedAuthADALWorkflowMSI

		p.adalWorkflow = fedAuthADALWorkflowMSI
		p.clientID = fedAuth.UserName

	case strings.EqualFold(fedAuth.FedAuthWorkflow, fedAuthActiveDirectoryApplication):
		fedAuth.FedAuthLibrary = fedAuthLibrarySecurityToken

		// Split the clientID@tenantID format
		p.clientID, p.tenantID = splitTenantAndClientID(fedAuth.UserName)
		if p.tenantID == "" {
			return fmt.Errorf("Expecting user id to be clientID@tenantID: found '%s'", fedAuth.UserName)
		}

		// Tenant ID should not be sent in login packet
		fedAuth.UserName = p.clientID

		if fedAuth.ClientCertPath != "" {
			if p.certificate, p.privateKey, err = getFedAuthClientCertificate(fedAuth.ClientCertPath, fedAuth.Password); err != nil {
				return err
			}
		} else {
			p.clientSecret = fedAuth.Password
		}

		// Password should not be sent in login packet
		fedAuth.Password = ""

	case fedAuth.FedAuthWorkflow == "":
		fedAuth.FedAuthLibrary = fedAuthLibraryReserved

	default:
		return fmt.Errorf("Invalid federated authentication type '%s': expected %s, %s, %s or %s",
			fedAuth.FedAuthWorkflow, fedAuthActiveDirectoryPassword, fedAuthActiveDirectoryMSI,
			fedAuthActiveDirectoryApplication, fedAuthActiveDirectoryIntegrated)
	}

	return nil
}

func splitTenantAndClientID(user string) (string, string) {
	// Split the user name into client id and tenant id at the @ symbol
	at := strings.IndexRune(user, '@')
	if at < 1 || at >= (len(user)-1) {
		return user, ""
	}

	return user[0:at], user[at+1:]
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
