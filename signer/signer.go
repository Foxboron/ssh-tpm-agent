package signer

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type TPMSigner struct {
	key *key.Key
	tpm func() transport.TPMCloser
	pin func(*key.Key) ([]byte, error)
}

var _ crypto.Signer = &TPMSigner{}

func NewTPMSigner(k *key.Key, tpm func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *TPMSigner {
	return &TPMSigner{
		key: k,
		tpm: tpm,
		pin: pin,
	}
}

func (t *TPMSigner) getTPM() transport.TPMCloser {
	return t.tpm()
}

func (t *TPMSigner) Public() crypto.PublicKey {
	pk, err := t.key.PublicKey()
	// This shouldn't happen!
	if err != nil {
		panic(err)
	}
	return pk
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

func newECCSigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}

func newRSASigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}

func (t *TPMSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var digestlength int
	var digestalg tpm2.TPMAlgID

	switch opts.HashFunc() {
	case crypto.SHA256:
		digestlength = 32
		digestalg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		digestlength = 48
		digestalg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		digestlength = 64
		digestalg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
	}

	if len(digest) != digestlength {
		return nil, fmt.Errorf("incorrect checksum length. expected %v got %v", digestlength, len(digest))
	}

	tpm := t.getTPM()
	defer tpm.Close()

	srkHandle, srkPublic, err := key.CreateSRK(tpm, t.key.Type)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	defer utils.FlushHandle(tpm, srkHandle)

	handle, err := key.LoadKeyWithParent(tpm, *srkHandle, t.key)
	if err != nil {
		return nil, err
	}
	defer utils.FlushHandle(tpm, handle)

	if t.key.PIN == key.HasPIN {
		p, err := t.pin(t.key)
		if err != nil {
			return nil, err
		}
		handle.Auth = tpm2.PasswordAuth(p)
	}

	var sigscheme tpm2.TPMTSigScheme
	switch t.key.Type {
	case tpm2.TPMAlgECDSA:
		sigscheme = newECCSigScheme(digestalg)
	case tpm2.TPMAlgRSA:
		sigscheme = newRSASigScheme(digestalg)
	}

	sign := tpm2.Sign{
		KeyHandle: *handle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme:  sigscheme,
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}

	switch t.key.Type {
	case tpm2.TPMAlgECDSA:
		eccsig, err := rspSign.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting signature: %v", err)
		}
		return encodeSignature(eccsig.SignatureR.Buffer, eccsig.SignatureS.Buffer)
	case tpm2.TPMAlgRSA:
		rsassa, err := rspSign.Signature.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting rsassa signature")
		}

		return rsassa.Sig.Buffer, nil
	}

	return nil, fmt.Errorf("failed returning signature")
}
