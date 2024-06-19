package keytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Represents the type for MkKey and mkImportableKey
type KeyFunc func(*testing.T, transport.TPMCloser, tpm2.TPMAlgID, int, []byte, string) (*key.Key, error)

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
func MkKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.Key, error) {
	t.Helper()
	return key.CreateKey(tpm, keytype, bits, []byte(""), 0x0, pin, comment)
}

// Helper to make an importable key
func MkImportableKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*key.Key, error) {
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
	return key.ImportKey(tpm, []byte(""), 0x0, pk, pin, comment)
}

// Give us some random bytes
func MustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
