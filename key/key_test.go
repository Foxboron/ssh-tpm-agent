package key_test

import (
	"crypto"
	"errors"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/internal/keytest"
	. "github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"crypto/ecdsa"
	"crypto/elliptic"
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
			k, err := CreateKey(tpm, c.alg, c.bits, []byte(""), []byte(""), "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, []byte(""), k)
			if err != nil {
				t.Fatalf("failed loading key: %v", err)
			}
			utils.FlushHandle(tpm, handle)
		})
	}
}

func TestCreateKeyWithOwnerPassword(t *testing.T) {
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

	ownerPassword := []byte("testPassword")

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

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			k, err := CreateKey(tpm, c.alg, c.bits, ownerPassword, []byte(""), "")
			if err != nil {
				t.Errorf("failed key import: %v", err)
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, ownerPassword, k)
			if err != nil {
				t.Errorf("failed loading key: %v", err)
			}
			utils.FlushHandle(tpm, handle)
		})
	}
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
			pk:   keytest.MkECDSA(t, elliptic.P256()),
		},
		{
			text: "p384",
			pk:   keytest.MkECDSA(t, elliptic.P384()),
		},
		{
			text: "p521",
			pk:   keytest.MkECDSA(t, elliptic.P521()),
			// Simulator doesn't like P521
			fail: true,
		},
		{
			text: "rsa2048",
			pk:   keytest.MkRSA(t, 2048),
		},
	} {
		t.Run(c.text, func(t *testing.T) {
			k, err := ImportKey(tpm, []byte(""), c.pk, []byte(""), "")
			if err != nil && c.fail {
				return
			}
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, []byte(""), k)
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
			pk:        keytest.MkECDSA(t, elliptic.P256()),
			bitlength: 256,
		},
		{
			text:      "p384",
			pk:        keytest.MkECDSA(t, elliptic.P384()),
			bitlength: 384,
		},
		{
			text: "p521",
			pk:   keytest.MkECDSA(t, elliptic.P521()),
			// Simulator doesn't like P521
			bitlength: 521,
			fail:      true,
		},
		{
			text:      "rsa2048",
			pk:        keytest.MkRSA(t, 2048),
			bitlength: 2048,
		},
	} {
		t.Run(c.text, func(t *testing.T) {
			k, err := ImportKey(tpm, []byte(""), c.pk, []byte(""), "")
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

func TestComment(t *testing.T) {
	cases := []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		comment string
		f       keytest.KeyFunc
	}{
		{
			text:    "create - p256",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			comment: string(keytest.MustRand(20)),
			f:       keytest.MkKey,
		},
		{
			text:    "imported - p256",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			comment: "this is a comment",
			f:       keytest.MkImportableKey,
		},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), c.comment)
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			if k.Description() != c.comment {
				t.Fatalf("failed to set comment: %v", err)
			}
		})
	}
}

func TestChangeAuth(t *testing.T) {
	cases := []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		oldPin  []byte
		newPin  []byte
		wanterr error
	}{
		{
			text:   "change pin",
			alg:    tpm2.TPMAlgECC,
			bits:   256,
			f:      keytest.MkKey,
			oldPin: []byte("123"),
			newPin: []byte("heyho"),
		},
		{
			text:   "change pin - empty to something",
			alg:    tpm2.TPMAlgECC,
			bits:   256,
			f:      keytest.MkImportableKey,
			oldPin: []byte(""),
			newPin: []byte("heyho"),
		},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, c.oldPin, "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			h := crypto.SHA256.New()
			h.Write([]byte(c.text))
			b := h.Sum(nil)

			_, err = Sign(tpm, []byte(""), k, b, c.oldPin, tpm2.TPMAlgSHA256)
			if err != nil {
				t.Fatalf("signing with correct pin should not fail: %v", err)
			}

			key, err := ChangeAuth(tpm, []byte(""), k, c.oldPin, c.newPin)
			if err != nil {
				t.Fatalf("ChangeAuth shouldn't fail: %v", err)
			}

			_, err = Sign(tpm, []byte(""), key, b, c.oldPin, tpm2.TPMAlgSHA256)
			if errors.Is(err, tpm2.TPMRCBadAuth) {
				t.Fatalf("old pin works on updated key")
			}

			_, err = Sign(tpm, []byte(""), key, b, c.newPin, tpm2.TPMAlgSHA256)
			if errors.Is(err, tpm2.TPMRCBadAuth) {
				t.Fatalf("new pin doesn't work")
			}
		})
	}
}
