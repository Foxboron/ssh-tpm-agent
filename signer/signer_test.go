package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestSigning(t *testing.T) {
	cases := []struct {
		msg        string
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
		},
		{
			msg:     "test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
		},
		{
			msg:        "test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
		},
		{
			msg:     "test encryption/decrypt - no pin for key, pin for sign",
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

			k, err := key.CreateKey(tpm, c.pin)
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

			if !ecdsa.VerifyASN1(pubkey, b[:], sig) {
				t.Fatalf("invalid signature")
			}

		})
	}
}
