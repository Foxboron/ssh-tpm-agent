package key

import (
	"crypto"
	"errors"
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
	key     *SSHTPMKey
	keyring *keyring.ThreadKeyring
}

// func (t *SSHKeySigner) Public() crypto.PublicKey {
// 	return t.TPMKeySigner.Public()
// }

func (t *SSHKeySigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	b, err := t.TPMKeySigner.Sign(r, digest, opts)
	if errors.Is(err, tpm2.TPMRCAuthFail) {
		slog.Debug("removed cached userauth for key", slog.Any("err", err), slog.String("desc", t.key.Description))
		t.keyring.RemoveKey(t.key.Fingerprint())
	}
	return b, err
}

func NewSSHKeySigner(k *SSHTPMKey, keyring *keyring.ThreadKeyring, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*keyfile.TPMKey) ([]byte, error)) *SSHKeySigner {
	return &SSHKeySigner{
		TPMKeySigner: keyfile.NewTPMKeySigner(k.TPMKey, ownerAuth, tpm, auth),
		keyring:      keyring,
		key:          k,
	}
}
