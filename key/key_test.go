package key

import (
	"reflect"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func TestCreateKey(t *testing.T) {
	cases := []struct {
		text string
		alg  tpm2.TPMAlgID
		bits int
	}{
		{
			text: "p256",
			alg:  tpm2.TPMAlgECDSA,
			bits: 256,
		},
		{
			text: "rsa",
			alg:  tpm2.TPMAlgRSA,
			bits: 2048,
		},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			k, err := CreateKey(tpm, c.alg, c.bits, []byte(""), []byte(""))
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, k)
			if err != nil {
				t.Fatalf("failed loading key: %v", err)
			}
			utils.FlushHandle(tpm, handle)
		})
	}
}

func mustPublic(data []byte) tpm2.TPM2BPublic {
	return tpm2.BytesAs2B[tpm2.TPMTPublic](data)
}

func mustPrivate(data []byte) tpm2.TPM2BPrivate {
	return tpm2.TPM2BPrivate{
		Buffer: data,
	}
}

func TestMarshalling(t *testing.T) {
	cases := []struct {
		text string
		k    *Key
	}{
		{
			text: "ecdsa/haspin",
			k: &Key{
				Version: 1,
				PIN:     HasPIN,
				Type:    tpm2.TPMAlgECDSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
			},
		},
		{
			text: "ecdsa/nopin",
			k: &Key{
				Version: 1,
				PIN:     NoPIN,
				Type:    tpm2.TPMAlgECDSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
			},
		},
		{
			text: "ecdsa/comment",
			k: &Key{
				Version: 1,
				PIN:     HasPIN,
				Type:    tpm2.TPMAlgECDSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
				Comment: []byte("This is a comment"),
			},
		},
		{
			text: "rsa/haspin",
			k: &Key{
				Version: 1,
				PIN:     HasPIN,
				Type:    tpm2.TPMAlgRSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
			},
		},
		{
			text: "rsa/nopin",
			k: &Key{
				Version: 1,
				PIN:     NoPIN,
				Type:    tpm2.TPMAlgRSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
			},
		},
		{
			text: "rsa/comment",
			k: &Key{
				Version: 1,
				PIN:     HasPIN,
				Type:    tpm2.TPMAlgRSA,
				Public:  mustPublic([]byte("public")),
				Private: mustPrivate([]byte("private")),
				Comment: []byte("This is a comment"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			b := EncodeKey(c.k)
			k, err := DecodeKey(b)
			if err != nil {
				t.Fatalf("test failed: %v", err)
			}

			if !reflect.DeepEqual(k, c.k) {
				t.Fatalf("keys are not the same")
			}
		})
	}
}

func TestECDSAImportKey(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err := ImportKey(tpm, *pk, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("failed key import: %v", err)
	}

	// Test if we can load the key
	// signer/signer_test.go tests the signing of the key
	_, err = LoadKey(tpm, k)
	if err != nil {
		t.Fatalf("failed loading key: %v", err)
	}
}

func TestRSAImportKey(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	k, err := ImportKey(tpm, *pk, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("failed key import: %v", err)
	}

	// Test if we can load the key
	// signer/signer_test.go tests the signing of the key
	_, err = LoadKey(tpm, k)
	if err != nil {
		t.Fatalf("failed loading key: %v", err)
	}
}
