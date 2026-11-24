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

// Test helper for CreateKey under a persistent parent
func MkPersistentParentKey(handle tpm2.TPMHandle) KeyFunc {
	return func(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.SSHTPMKey, error) {
		t.Helper()
		srk, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(tpm)
		if err != nil {
			t.Fatalf("failed creating primary key: %v", err)
		}
		defer keyfile.FlushHandle(tpm, srk.ObjectHandle)

		_, err = tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: tpm2.NamedHandle{
				Handle: srk.ObjectHandle,
				Name:   srk.Name,
			},
			PersistentHandle: handle,
		}.Execute(tpm)
		if err != nil {
			t.Fatalf("failed persisting primary key: %v", err)
		}
		// The persistent copy outlives the flush of the transient one: evict
		// it once the test is done.
		t.Cleanup(func() {
			if _, err := (tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: tpm2.NamedHandle{
					Handle: handle,
					Name:   srk.Name,
				},
				PersistentHandle: handle,
			}).Execute(tpm); err != nil {
				t.Errorf("failed evicting persistent primary key: %v", err)
			}
		})

		return key.NewSSHTPMKey(tpm, keytype, bits, []byte(""),
			keyfile.WithParent(handle),
			keyfile.WithUserAuth(pin),
			keyfile.WithDescription(comment),
		)
	}
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
		func(_ key.SSHTPMKeys) ([]byte, *keyring.Key, error) {
			return []byte(""), nil, nil
		},
	)
}
