package key

import (
	"errors"
	"fmt"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	ECCSRK_H10_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			AdminWithPolicy:     false,
			SignEncrypt:         true,
			Decrypt:             true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
				0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
				0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
				0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
				0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
				0xB7, 0xA0,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}

	RSASRK_H9_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			AdminWithPolicy:     false,
			SignEncrypt:         true,
			Decrypt:             true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: []byte{
				0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
				0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
				0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
				0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
				0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
				0xB7, 0xA0,
			},
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 0)},
		),
	}
)

type HierSSHTPMKey struct {
	*SSHTPMKey
	handle *tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// from crypto/ecdsa
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// from crypto/ecdsa
func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

func (h *HierSSHTPMKey) Sign(tpm transport.TPMCloser, ownerauth, auth, digest []byte, digestalgo tpm2.TPMAlgID) ([]byte, error) {
	var digestlength int
	var err error

	switch digestalgo {
	case tpm2.TPMAlgSHA256:
		digestlength = 32
	case tpm2.TPMAlgSHA384:
		digestlength = 48
	case tpm2.TPMAlgSHA512:
		digestlength = 64
	default:
		return nil, fmt.Errorf("%v is not a supported hashing algorithm", digestalgo)
	}

	if len(digest) != digestlength {
		return nil, fmt.Errorf("incorrect checksum length. expected %v got %v", digestlength, len(digest))
	}

	var sigscheme tpm2.TPMTSigScheme
	switch h.KeyAlgo() {
	case tpm2.TPMAlgECC:
		sigscheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: digestalgo,
				},
			),
		}
	case tpm2.TPMAlgRSA:
		sigscheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: digestalgo,
				},
			),
		}
	}

	sign := tpm2.Sign{
		KeyHandle: &tpm2.AuthHandle{
			Handle: *h.handle,
			Name:   h.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest:   tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: sigscheme,
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	switch h.KeyAlgo() {
	case tpm2.TPMAlgECC:
		eccsig, err := (&rspSign.Signature.Signature).ECDSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting signature: %v", err)
		}
		return encodeSignature(eccsig.SignatureR.Buffer, eccsig.SignatureS.Buffer)
	case tpm2.TPMAlgRSA:
		rsassa, err := (&rspSign.Signature.Signature).RSASSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting rsassa signature")
		}
		return rsassa.Sig.Buffer, nil
	}
	return nil, fmt.Errorf("failed returning signature")
}

func (h *HierSSHTPMKey) FlushHandle(tpm transport.TPMCloser) {
	if h.handle != nil {
		keyfile.FlushHandle(tpm, *h.handle)
	}
}

func (h *HierSSHTPMKey) Signer(keyring *keyring.ThreadKeyring, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*keyfile.TPMKey) ([]byte, error)) *SSHKeySigner {
	return NewSSHKeySigner(h, keyring, ownerAuth, tpm, auth)
}

func CreateHierarchyKey(tpm transport.TPMCloser, keytype tpm2.TPMAlgID, hier tpm2.TPMHandle, desc string) (*HierSSHTPMKey, error) {
	var tmpl tpm2.TPMTPublic
	switch keytype {
	case tpm2.TPMAlgECC:
		tmpl = ECCSRK_H10_Template
	case tpm2.TPMAlgRSA:
		tmpl = RSASRK_H9_Template
	}

	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hier,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tmpl),
	}

	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, err
	}

	var tpmkey keyfile.TPMKey
	tpmkey.AddOptions(
		keyfile.WithUserAuth([]byte(nil)),
		keyfile.WithPubkey(rsp.OutPublic),
		keyfile.WithDescription(desc),
	)

	wkey, err := WrapTPMKey(&tpmkey)
	if err != nil {
		return nil, err
	}

	return &HierSSHTPMKey{
		SSHTPMKey: wkey,
		handle:    &rsp.ObjectHandle,
		name:      rsp.Name,
	}, nil
}
