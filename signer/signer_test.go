package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestSigning(t *testing.T) {
	cases := []struct {
		msg        string
		keytype    tpm2.TPMAlgID
		bits       int
		digest     crypto.Hash
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "ecdsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:        "ecdsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgECC,
			digest:     crypto.SHA256,
			bits:       256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:        "rsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgRSA,
			digest:     crypto.SHA256,
			bits:       2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := key.CreateKey(tpm, c.keytype, c.bits, []byte(""), 0x0, c.pin, "")
			if err != nil {
				t.Fatalf("%v", err)
			}

			signer := NewTPMSigner(k,
				func() ([]byte, error) { return []byte(""), nil },
				0x0,
				func() transport.TPMCloser { return tpm },
				func(_ *key.Key) ([]byte, error) { return c.signpin, nil },
			)

			// Empty reader, we don't use this
			var r io.Reader

			sig, err := signer.Sign(r, b[:], c.digest)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			pubkey, err := k.PublicKey()
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed getting pubkey: %v", err)
			}

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			switch pk := pubkey.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pk, b[:], sig) {
					t.Fatalf("invalid signature")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pk, c.digest, b[:], sig); err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestSigningWithOwnerPassword(t *testing.T) {
	ownerPassword := []byte("testPassword")

	cases := []struct {
		msg           string
		keytype       tpm2.TPMAlgID
		bits          int
		digest        crypto.Hash
		filekey       []byte
		pin           []byte
		signpin       []byte
		ownerpassword []byte
		shouldfail    bool
	}{
		{
			msg:           "ecdsa - test encryption/decrypt - no pin",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - pin",
			filekey:       []byte("this is a test filekey"),
			pin:           []byte("123"),
			signpin:       []byte("123"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - no pin - invalid owner password",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			shouldfail:    true,
			ownerpassword: []byte("invalidPassword"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			hca := tpm2.HierarchyChangeAuth{
				AuthHandle: tpm2.TPMRHOwner,
				NewAuth: tpm2.TPM2BAuth{
					Buffer: ownerPassword,
				},
			}
			_, err = hca.Execute(tpm)
			if err != nil {
				t.Errorf("failed HierarchyChangeAuth: %v", err)
			}

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := key.CreateKey(tpm, c.keytype, c.bits, c.ownerpassword, 0x0, c.pin, "")
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			signer := NewTPMSigner(k,
				func() ([]byte, error) { return c.ownerpassword, nil },
				0x0,
				func() transport.TPMCloser { return tpm },
				func(_ *key.Key) ([]byte, error) { return c.signpin, nil },
			)

			// Empty reader, we don't use this
			var r io.Reader

			sig, err := signer.Sign(r, b[:], c.digest)
			if err != nil {
				t.Fatalf("%v", err)
			}

			pubkey, err := k.PublicKey()
			if err != nil {
				t.Fatalf("failed getting pubkey: %v", err)
			}

			if err != nil {
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			switch pk := pubkey.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pk, b[:], sig) {
					t.Fatalf("invalid signature")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pk, c.digest, b[:], sig); err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestSigningWithImportedKey(t *testing.T) {
	cases := []struct {
		msg        string
		keytype    tpm2.TPMAlgID
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "ecdsa encryption/decrypt - no pin",
			keytype: tpm2.TPMAlgECC,
			filekey: []byte("this is a test filekey"),
		},
		{
			msg:     "ecdsa encryption/decrypt - pin",
			keytype: tpm2.TPMAlgECC,
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
		},
		{
			msg:        "ecdsa encryption/decrypt - no pin for sign",
			keytype:    tpm2.TPMAlgECC,
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
		},
		{
			msg:     "rsa encryption/decrypt - no pin for key, pin for sign",
			keytype: tpm2.TPMAlgRSA,
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
		},
		{
			msg:     "rsa encryption/decrypt - no pin",
			keytype: tpm2.TPMAlgRSA,
			filekey: []byte("this is a test filekey"),
		},
		{
			msg:     "rsa encryption/decrypt - pin",
			keytype: tpm2.TPMAlgRSA,
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
		},
		{
			msg:        "rsa encryption/decrypt - no pin for sign",
			keytype:    tpm2.TPMAlgRSA,
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
		},
		{
			msg:     "rsa encryption/decrypt - no pin for key, pin for sign",
			keytype: tpm2.TPMAlgRSA,
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			b := sha256.Sum256([]byte("heyho"))

			var pk any
			if c.keytype == tpm2.TPMAlgECC {
				p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate ecdsa key: %v", err)
				}
				pk = *p
			} else if c.keytype == tpm2.TPMAlgRSA {
				p, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("failed to generate ecdsa key: %v", err)
				}
				pk = *p
			}

			k, err := key.ImportKey(tpm, []byte(""), 0x0, pk, c.pin, "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			signer := NewTPMSigner(k,
				func() ([]byte, error) { return []byte(""), nil },
				0x0,
				func() transport.TPMCloser { return tpm },
				func(_ *key.Key) ([]byte, error) { return c.signpin, nil },
			)

			// Empty reader, we don't use this
			var r io.Reader

			sig, err := signer.Sign(r, b[:], crypto.SHA256)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			pubkey, err := k.PublicKey()
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed getting pubkey: %v", err)
			}

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			switch pk := pubkey.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pk, b[:], sig) {
					t.Fatalf("invalid signature")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, b[:], sig); err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			}

		})
	}
}
