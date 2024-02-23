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
			alg:  tpm2.TPMAlgECC,
			bits: 256,
		},
		{
			text: "p384",
			alg:  tpm2.TPMAlgECC,
			bits: 384,
		},
		{
			text: "p521",
			alg:  tpm2.TPMAlgECC,
			bits: 521,
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

func mkRSA(t *testing.T, bits int) rsa.PrivateKey {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	return *pk
}

func mkECDSA(t *testing.T, a elliptic.Curve) ecdsa.PrivateKey {
	t.Helper()
	pk, err := ecdsa.GenerateKey(a, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	return *pk
}

func TestImport(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range []struct {
		text string
		pk   any
		fail bool
	}{
		{
			text: "p256",
			pk:   mkECDSA(t, elliptic.P256()),
		},
		{
			text: "p384",
			pk:   mkECDSA(t, elliptic.P384()),
		},
		{
			text: "p521",
			pk:   mkECDSA(t, elliptic.P521()),
			// Simulator doesn't like P521
			fail: true,
		},
		{
			text: "rsa2048",
			pk:   mkRSA(t, 2048),
		},
	} {
		t.Run(c.text, func(t *testing.T) {
			k, err := ImportKey(tpm, c.pk, []byte(""), []byte(""))
			if err != nil && c.fail {
				return
			}
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

func TestKeyPublickey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range []struct {
		text      string
		pk        any
		bitlength int
		fail      bool
	}{
		{
			text:      "p256",
			pk:        mkECDSA(t, elliptic.P256()),
			bitlength: 256,
		},
		{
			text:      "p384",
			pk:        mkECDSA(t, elliptic.P384()),
			bitlength: 384,
		},
		{
			text: "p521",
			pk:   mkECDSA(t, elliptic.P521()),
			// Simulator doesn't like P521
			bitlength: 521,
			fail:      true,
		},
		{
			text:      "rsa2048",
			pk:        mkRSA(t, 2048),
			bitlength: 2048,
		},
	} {
		t.Run(c.text, func(t *testing.T) {
			k, err := ImportKey(tpm, c.pk, []byte(""), []byte(""))
			if err != nil && c.fail {
				return
			}
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			pubkey, err := k.PublicKey()
			if err != nil {
				t.Fatalf("failed getting public key: %v", err)
			}
			switch pk := pubkey.(type) {
			case *ecdsa.PublicKey:
				if pk.Params().BitSize != c.bitlength {
					t.Fatalf("wrong import, expected %v got %v bitlength", pk.Params().BitSize, c.bitlength)
				}
			case *rsa.PublicKey:
				if pk.N.BitLen() != c.bitlength {
					t.Fatalf("wrong import, expected %v got %v bitlength", pk.N.BitLen(), c.bitlength)
				}
			}
		})
	}
}
