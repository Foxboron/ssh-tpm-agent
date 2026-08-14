package key

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/secret"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
)

// Shim for keyfile.TPMKeySigner
// We need access to the SSHTPMKey to change the userauth for caching
type SSHKeySigner struct {
	key       SSHTPMKeys
	keyring   *keyring.ThreadKeyring
	tpm       func() transport.TPMCloser
	ownerauth func() ([]byte, error)

	// auth returns the userauth bytes along with the locked buffer backing
	// them if present.
	auth func(*keyfile.TPMKey) ([]byte, error)
}

var _ crypto.Signer = &SSHKeySigner{}

func (t *SSHKeySigner) Public() crypto.PublicKey {
	pk, err := t.key.GetTPMKey().PublicKey()
	// This shouldn't happen!
	if err != nil {
		panic(fmt.Errorf("failed producing public: %v", err))
	}
	return pk
}

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
		var secretBytes []byte
		if os.Getenv("AVOID_SECRET") == "1" {
			slog.Info("Avoiding runtime/secret.Do")
			secretBytes, err = t.signKey(key, r, digest, opts)
		} else {
			slog.Info("Using runtime/secret.Do")
			secret.Do(func() { secretBytes, err = t.signKey(key, r, digest, opts) })
		}
		runtime.GC()
		if secretBytes != nil {
			b = make([]byte, len(secretBytes))
			if len(secretBytes) != copy(b, secretBytes) {
				return nil, fmt.Errorf("Failed to copy all signing bytes for downstream consumption")
			}
		}
	default:
		return nil, fmt.Errorf("this should not happen")
	}

	if errors.Is(err, tpm2.TPMRCAuthFail) {
		slog.Debug("removed cached userauth for key", slog.Any("err", err), slog.String("desc", t.key.GetDescription()))
		t.keyring.RemoveKey(t.key.Fingerprint())
	}
	return b, err
}

// signKey wraps t.auth to ensure its buffer is wiped and freed before signKey returns.
func (t *SSHKeySigner) signKey(k *SSHTPMKey, r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var passphrases [][]byte
	defer func() {
		for _, passphrase := range passphrases {
			clear(passphrase)
			runtime.KeepAlive(passphrase)
		}
	}()

	return keyfile.NewTPMKeySigner(k.TPMKey, t.ownerauth, t.tpm,
		func(tk *keyfile.TPMKey) ([]byte, error) {
			key, err := t.auth(tk)
			passphrases = append(passphrases, key)
			if err != nil {
				return nil, err
			}
			return key, nil
		},
	).Sign(r, digest, opts)
}

func NewSSHKeySigner(k SSHTPMKeys, keyring *keyring.ThreadKeyring, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*keyfile.TPMKey) ([]byte, error)) *SSHKeySigner {
	return &SSHKeySigner{
		keyring:   keyring,
		tpm:       tpm,
		ownerauth: ownerAuth,
		auth:      auth,
		key:       k,
	}
}
