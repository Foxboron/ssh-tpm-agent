package keytest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"path"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Represents the type for MkKey and mkImportableKey
type KeyFunc func(*testing.T, transport.TPMCloser, tpm2.TPMAlgID, int, []byte, string) (*key.SSHTPMKey, error)

func MkRSA(t *testing.T, bits int) rsa.PrivateKey {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	return *pk
}

func MkECDSA(t *testing.T, a elliptic.Curve) ecdsa.PrivateKey {
	t.Helper()
	pk, err := ecdsa.GenerateKey(a, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	return *pk
}

// Test helper for CreateKey
func MkKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.SSHTPMKey, error) {
	t.Helper()
	return key.NewSSHTPMKey(tpm, keytype, bits, []byte(""),
		keyfile.WithUserAuth(pin),
		keyfile.WithDescription(comment),
	)
}

func MkCertificate(t *testing.T, ca crypto.Signer) KeyFunc {
	t.Helper()
	return func(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.SSHTPMKey, error) {
		k, err := MkKey(t, tpm, keytype, bits, pin, comment)
		if err != nil {
			t.Fatalf("message")
		}

		signer, err := ssh.NewSignerFromKey(ca)
		if err != nil {
			t.Fatalf("unable to generate signer from key: %v", err)
		}
		mas, err := ssh.NewSignerWithAlgorithms(signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
		if err != nil {
			t.Fatalf("unable to create signer with algorithms: %v", err)
		}

		k.Certificate = &ssh.Certificate{
			Key:      *k.PublicKey,
			CertType: ssh.UserCert,
		}
		if err := k.Certificate.SignCert(rand.Reader, mas); err != nil {
			t.Fatalf("unable to sign certificate: %v", err)
		}

		return k, nil
	}
}

// Helper to make an importable key
func MkImportableKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.SSHTPMKey, error) {
	t.Helper()
	var pk any
	switch keytype {
	case tpm2.TPMAlgECC:
		switch bits {
		case 256:
			pk = MkECDSA(t, elliptic.P256())
		case 384:
			pk = MkECDSA(t, elliptic.P384())
		case 521:
			pk = MkECDSA(t, elliptic.P521())
		}
	case tpm2.TPMAlgRSA:
		pk = MkRSA(t, bits)
	}
	return key.NewImportedSSHTPMKey(tpm, pk, []byte(""),
		keyfile.WithUserAuth(pin),
		keyfile.WithDescription(comment))
}

// Give us some random bytes
func MustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

func NewTestAgent(t *testing.T, tpm transport.TPMCloser) *agent.Agent {
	unixList, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path.Join(t.TempDir(), "socket")})
	if err != nil {
		t.Fatalf("failed listening: %v", err)
	}
	return agent.NewAgent(unixList,
		[]sshagent.ExtendedAgent{},
		func() *keyring.ThreadKeyring { return &keyring.ThreadKeyring{} },
		func() transport.TPMCloser { return tpm },
		func() ([]byte, error) { return []byte(""), nil },
		func(_ key.SSHTPMKeys) ([]byte, error) {
			return []byte(""), nil
		},
	)
}
