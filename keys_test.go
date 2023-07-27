package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestSigning(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := createKey(tpm, []byte(""))
	if err != nil {
		t.Fatalf("%v", err)
	}

	b := sha256.Sum256([]byte("heyho"))

	signer := NewTPMSigner(k, func() transport.TPMCloser { return tpm })

	// Empty reader, we don't use this
	var r io.Reader

	sig, err := signer.Sign(r, b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pubkey, err := k.PublicKey()
	if err != nil {
		t.Fatalf("failed getting pubkey: %v", err)
	}

	if !ecdsa.VerifyASN1(pubkey, b[:], sig) {
		t.Fatalf("invalid signature")
	}
}
