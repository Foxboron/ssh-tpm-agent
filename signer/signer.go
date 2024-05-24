package signer

import (
	"crypto"
	"fmt"
	"io"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMSigner struct {
	key           *key.Key
	ownerPassword func() ([]byte, error)
	srkHandle     tpm2.TPMHandle
	tpm           func() transport.TPMCloser
	pin           func(*key.Key) ([]byte, error)
}

var _ crypto.Signer = &TPMSigner{}

func NewTPMSigner(k *key.Key, ownerPassword func() ([]byte, error), srkHandle tpm2.TPMHandle, tpm func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *TPMSigner {
	return &TPMSigner{
		key:           k,
		ownerPassword: ownerPassword,
		srkHandle:     srkHandle,
		tpm:           tpm,
		pin:           pin,
	}
}

func (t *TPMSigner) Public() crypto.PublicKey {
	pk, err := t.key.PublicKey()
	// This shouldn't happen!
	if err != nil {
		panic(err)
	}
	return pk
}

func (t *TPMSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var digestalg tpm2.TPMAlgID

	auth := []byte("")
	if t.key.TPMKey.HasAuth() {
		p, err := t.pin(t.key)
		if err != nil {
			return nil, err
		}
		auth = p
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		digestalg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		digestalg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		digestalg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
	}

	ownerPassword, err := t.ownerPassword()
	if err != nil {
		return nil, err
	}

	return key.Sign(t.tpm(), ownerPassword, t.srkHandle, t.key, digest, auth, digestalg)
}
