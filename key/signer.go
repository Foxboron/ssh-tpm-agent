package key

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
)

// Shim for keyfile.TPMKeySigner
// We need access to the SSHTPMKey to change the userauth for caching
type SSHKeySigner struct {
	*keyfile.TPMKeySigner
	key       SSHTPMKeys
	keyring   *keyring.ThreadKeyring
	tpm       func() transport.TPMCloser
	ownerauth func() ([]byte, error)
}

var _ crypto.Signer = &SSHKeySigner{}

func (t *SSHKeySigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var b []byte
	var err error
	switch key := t.key.(type) {
	case *HierSSHTPMKey:
		var digestalg tpm2.TPMAlgID
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
		b, err = key.Sign(t.tpm(), []byte(nil), []byte(nil), digest, digestalg)
	case *SSHTPMKey:
		b, err = t.TPMKeySigner.Sign(r, digest, opts)
	default:
		return nil, fmt.Errorf("this should not happen")
	}

	if errors.Is(err, tpm2.TPMRCAuthFail) {
		slog.Debug("removed cached userauth for key", slog.Any("err", err), slog.String("desc", t.key.GetDescription()))
		t.keyring.RemoveKey(t.key.Fingerprint())
	}
	return b, err
}

func NewSSHKeySigner(k SSHTPMKeys, keyring *keyring.ThreadKeyring, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*keyfile.TPMKey) ([]byte, error)) *SSHKeySigner {
	return &SSHKeySigner{
		TPMKeySigner: keyfile.NewTPMKeySigner(k.GetTPMKey(), ownerAuth, tpm, auth),
		keyring:      keyring,
		tpm:          tpm,
		ownerauth:    ownerAuth,
		key:          k,
	}
}
