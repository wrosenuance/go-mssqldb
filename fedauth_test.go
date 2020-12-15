package mssql

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

var fedAuthConfigurerLock = &sync.Mutex{}

type testFedAuthConfigurer struct {
	clientID, clientSecret string
	tenantID               string
	user, password         string
	cert                   bool
	key                    bool
}

func (fa *testFedAuthConfigurer) Reset() {
	fa.clientID = ""
	fa.clientSecret = ""
	fa.tenantID = ""
	fa.user = ""
	fa.password = ""
	fa.cert = false
	fa.key = false
}

func (fa *testFedAuthConfigurer) SecurityTokenProviderFromCertificate(clientID, tenantID string, cert *x509.Certificate, key *rsa.PrivateKey) SecurityTokenProvider {
	fa.clientID = clientID
	fa.tenantID = tenantID
	fa.cert = cert != nil
	fa.key = key != nil

	return func(ctx context.Context) (string, error) {
		return "<token>", nil
	}
}

func (fa *testFedAuthConfigurer) SecurityTokenProviderFromSecret(clientID, tenantID, clientSecret string) SecurityTokenProvider {
	fa.clientID = clientID
	fa.tenantID = tenantID
	fa.clientSecret = clientSecret

	return func(ctx context.Context) (string, error) {
		return "<token>", nil
	}
}

func (fa *testFedAuthConfigurer) ActiveDirectoryTokenProviderFromPassword(user, password string) ActiveDirectoryTokenProvider {
	fa.user = user
	fa.password = password

	return func(ctx context.Context, stsURL, spn string) (string, error) {
		return "<token>", nil
	}
}

func (fa *testFedAuthConfigurer) ActiveDirectoryTokenProviderFromIdentity(clientID string) ActiveDirectoryTokenProvider {
	fa.clientID = clientID

	return func(ctx context.Context, stsURL, spn string) (string, error) {
		return "<token>", nil
	}
}

func TestFedAuthConfigurer(t *testing.T) {
	configurer := &testFedAuthConfigurer{}

	fedAuthConfigurerLock.Lock()
	SetFederatedAuthenticationConfigurer(configurer)

	defer func() {
		SetFederatedAuthenticationConfigurer(nil)
		fedAuthConfigurerLock.Unlock()
	}()

	passphrase := "SuperSecret7"
	certBlock, _, encryptedKeyBlock, err := generateTestCertAndKey(passphrase)
	if err != nil {
		t.Logf("Unable to generate certificate and keys: %v", err)
		t.FailNow()
	}

	pemFile, err := writePEMBlocksToFile([]*pem.Block{certBlock, encryptedKeyBlock})
	if err != nil {
		t.Logf("Unable to write certificate and encrypted key to temporary file: %v", err)
		t.FailNow()
	}

	defer func() {
		os.Remove(pemFile)
	}()

	tests := []struct {
		name        string
		dsn         string
		expected    *testFedAuthConfigurer
		expectError bool
	}{
		{
			name:        "no fed auth configured",
			dsn:         "server=localhost",
			expected:    &testFedAuthConfigurer{},
			expectError: false,
		},
		{
			name: "application with cert/key",
			dsn:  "server=localhost;fedauth=ActiveDirectoryApplication;user id=service-principal-id@tenant-id;password=" + passphrase + ";clientcertpath=" + pemFile,
			expected: &testFedAuthConfigurer{
				clientID: "service-principal-id",
				tenantID: "tenant-id",
				cert:     true,
				key:      true,
			},
			expectError: false,
		},
		{
			name:        "application with invalid cert/key",
			dsn:         "server=localhost;fedauth=ActiveDirectoryApplication;user id=service-principal-id@tenant-id;clientcertpath=" + pemFile,
			expected:    &testFedAuthConfigurer{},
			expectError: true,
		},
		{
			name: "application with secret",
			dsn:  "server=localhost;fedauth=ActiveDirectoryApplication;user id=service-principal-id@tenant-id;password=" + passphrase,
			expected: &testFedAuthConfigurer{
				clientID:     "service-principal-id",
				tenantID:     "tenant-id",
				clientSecret: passphrase,
			},
			expectError: false,
		},
		{
			name: "user with password",
			dsn:  "server=localhost;fedauth=ActiveDirectoryPassword;user id=azure-ad-user;password=azure-ad-password",
			expected: &testFedAuthConfigurer{
				user:     "azure-ad-user",
				password: "azure-ad-password",
			},
			expectError: false,
		},
		{
			name:        "managed identity without client id",
			dsn:         "server=localhost;fedauth=ActiveDirectoryMSI",
			expected:    &testFedAuthConfigurer{},
			expectError: false,
		},
		{
			name: "managed identity with client id",
			dsn:  "server=localhost;fedauth=ActiveDirectoryMSI;user id=identity-client-id",
			expected: &testFedAuthConfigurer{
				clientID: "identity-client-id",
			},
			expectError: false,
		},
	}

	for _, tst := range tests {
		configurer.Reset()

		c, err := NewConnector(tst.dsn)
		if err != nil {
			t.Log("Unable to parse test DSN")
			t.FailNow()
		}

		err = c.checkFedAuthProviders(&c.params)
		if !tst.expectError && err != nil {
			t.Errorf("Error returned when none expected in test case '%s': %v", tst.name, err)
		} else if tst.expectError && err == nil {
			t.Errorf("No error returned when error expected in test case '%s'", tst.name)
		} else if (*configurer) != (*tst.expected) {
			t.Errorf("Captured parameters do not match in test caes '%s'", tst.name)
		}
	}
}

func TestGetFedAuthClientCertificate(t *testing.T) {
	passphrase := "SuperSecret7"
	certBlock, keyBlock, encryptedKeyBlock, err := generateTestCertAndKey(passphrase)
	if err != nil {
		t.Logf("Unable to generate certificate and keys: %v", err)
		t.FailNow()
	}

	expectValid := func(name string) func(*x509.Certificate, *rsa.PrivateKey, error) {
		return func(cert *x509.Certificate, key *rsa.PrivateKey, err error) {
			if err != nil {
				t.Errorf("Error loading %s test case certificate and key: %v", name, err)
			} else {
				if cert == nil {
					t.Errorf("Expected cert but found nil in %s test case", name)
				}

				if key == nil {
					t.Errorf("Expected key but found nil in %s test case", name)
				}
			}
		}
	}

	expectError := func(name string) func(*x509.Certificate, *rsa.PrivateKey, error) {
		return func(cert *x509.Certificate, key *rsa.PrivateKey, err error) {
			if err == nil {
				t.Errorf("Did not get expected error while loading %s test case certificate and key", name)
			}
		}
	}

	tests := []struct {
		name           string
		blocks         []*pem.Block
		loadPassphrase string
		verifier       func(certificate *x509.Certificate, privateKey *rsa.PrivateKey, err error)
	}{
		{
			name:           "valid unencrypted",
			blocks:         []*pem.Block{certBlock, keyBlock},
			loadPassphrase: "",
			verifier:       expectValid("unencrypted"),
		},
		{
			name:           "valid encrypted",
			blocks:         []*pem.Block{certBlock, encryptedKeyBlock},
			loadPassphrase: passphrase,
			verifier:       expectValid("encrypted"),
		},
		{
			name:           "empty",
			blocks:         []*pem.Block{},
			loadPassphrase: "",
			verifier:       expectError("empty"),
		},
		{
			name:           "bogus block type",
			blocks:         []*pem.Block{&pem.Block{Type: "HOT GARBAGE", Bytes: []byte("HOTGARBAGE==")}},
			loadPassphrase: "",
			verifier:       expectError("bogus block type"),
		},
		{
			name:           "bogus certificate",
			blocks:         []*pem.Block{&pem.Block{Type: "CERTIFICATE", Bytes: []byte("HOTGARBAGE==")}},
			loadPassphrase: "",
			verifier:       expectError("bogus certificate"),
		},
		{
			name:           "no private key",
			blocks:         []*pem.Block{certBlock},
			loadPassphrase: "",
			verifier:       expectError("no private key"),
		},
		{
			name:           "bogus private key",
			blocks:         []*pem.Block{certBlock, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("HOTGARBAGE==")}},
			loadPassphrase: "",
			verifier:       expectError("bogus private key"),
		},
		{
			name:           "bogus encrypted private key",
			blocks:         []*pem.Block{certBlock, &pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"DEK-Info": "AlsoGarbage"}, Bytes: []byte("HOTGARBAGE==")}},
			loadPassphrase: "",
			verifier:       expectError("bogus encrypted private key"),
		},
	}

	for _, tst := range tests {
		pemFile, err := writePEMBlocksToFile(tst.blocks)
		if err != nil {
			t.Logf("Unable to write PEM blocks for test case %s: %v", tst.name, err)
			t.FailNow()
		}

		func() {
			defer func() { os.Remove(pemFile) }()

			cert, key, err := getFedAuthClientCertificate(pemFile, tst.loadPassphrase)

			tst.verifier(cert, key, err)
		}()
	}
}

func generateTestCertAndKey(passphrase string) (*pem.Block, *pem.Block, *pem.Block, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}

	encryptedKeyBlock, err := x509.EncryptPEMBlock(rand.Reader, keyBlock.Type, keyBlock.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"go-mssqldb"},
		},
		NotBefore: time.Now().Add(-(time.Minute * 5)),
		NotAfter:  time.Now().Add(time.Hour * 24),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}

	return certBlock, keyBlock, encryptedKeyBlock, nil
}

func writePEMBlocksToFile(blocks []*pem.Block) (string, error) {
	f, err := ioutil.TempFile("", "go-mssql-azureauth-")
	if err != nil {
		return "", err
	}

	for _, block := range blocks {
		if err = pem.Encode(f, block); err != nil {
			return "", err
		}
	}

	if err = f.Close(); err != nil {
		return "", err
	}

	return f.Name(), nil
}
