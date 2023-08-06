package signer

import (
	"crypto"
	"crypto/ecdsa"
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
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "ecdsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgECDSA,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECDSA,
		},
		{
			msg:        "ecdsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgECDSA,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECDSA,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgRSA,
		},
		{
			msg:     "rsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
		},
		{
			msg:        "rsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgRSA,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
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

			k, err := key.CreateKey(tpm, c.keytype, c.pin)
			if err != nil {
				t.Fatalf("%v", err)
			}

			signer := NewTPMSigner(k,
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
