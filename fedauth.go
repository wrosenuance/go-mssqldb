package mssql

import (
	"context"
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

// FederatedAuthenticationState tracks federated authentication state before and during login
type FederatedAuthenticationState struct {
	// FedAuthWorkflow captures the "fedauth" connection parameter
	FedAuthWorkflow string

	// UserName is initially set to the user id connection parameter.
	// The federated authentication configurer can modify this value to
	// change what is sent in the login packet.
	UserName string

	// Password is initially set to the user id connection parameter.
	// The federated authentication configurer can modify this value to
	// change what is sent in the login packet.
	Password string

	// Password is initially set to the client cert path connection parameter.
	ClientCertPath string

	// FedAuthLibrary is populated by the federated authentication provider.
	FedAuthLibrary int

	// ADALWorkflow is populated by the federated authentication provider.
	ADALWorkflow byte

	// FedAuthEcho is populated from the prelogin response
	FedAuthEcho bool

	// FedAuthToken is populated during login with the value from the provider.
	FedAuthToken string

	// Nonce is populated during login with the value from the provider.
	Nonce []byte

	// Signature is populated during login with the value from the server.
	Signature []byte
}

// FederatedAuthenticationProvider implementations use the connection string
// parameters to determine the library and workflow, if any, and obtain tokens
// during the login sequence.
type FederatedAuthenticationProvider interface {
	// Configure accepts the incoming connection parameters and determines
	// the values for the authentication library and ADAL workflow.
	ConfigureProvider(fedAuth *FederatedAuthenticationState) error

	// ProvideActiveDirectoryToken implementations are called during federated
	// authentication login sequences where the server provides a service
	// principal name and security token service endpoint that should be used
	// to obtain the token. Implementations should contact the security token
	// service specified and obtain the appropriate token, or return an error
	// to indicate why a token is not available.
	ProvideActiveDirectoryToken(ctx context.Context, serverSPN, stsURL string) (string, error)

	// ProvideSecurityToken implementations are called during federated
	// authentication security token login sequences at the point when the
	// security token is required.  The string returned should be the access
	// token to supply to the server, otherwise an error can be returned to
	// indicate why a token is not available.
	ProvideSecurityToken(ctx context.Context) (string, error)
}
