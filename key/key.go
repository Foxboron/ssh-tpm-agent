package key

import (
	"errors"
	"fmt"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var (
	ErrOldKey = errors.New("old format on key")
)

// SSHTPMKey is a wrapper for TPMKey implementing the ssh.PublicKey specific parts
type SSHTPMKey struct {
	*keyfile.TPMKey
	Userauth    []byte
	Certificate *ssh.Certificate
}

func NewSSHTPMKey(tpm transport.TPMCloser, alg tpm2.TPMAlgID, bits int, ownerauth []byte, fn ...keyfile.TPMKeyOption) (*SSHTPMKey, error) {
	k, err := keyfile.NewLoadableKey(
		tpm, alg, bits, ownerauth, fn...,
	)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k, nil, nil}, nil
}

// This assumes we are just getting a local PK.
func NewImportedSSHTPMKey(tpm transport.TPMCloser, pk any, ownerauth []byte, fn ...keyfile.TPMKeyOption) (*SSHTPMKey, error) {
	sess := keyfile.NewTPMSession(tpm)
	srkHandle, srkPub, err := keyfile.CreateSRK(sess, tpm2.TPMRHOwner, ownerauth)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	sess.SetSalted(srkHandle.Handle, *srkPub)
	defer sess.FlushHandle()

	k, err := keyfile.NewImportablekey(
		srkPub, pk, fn...)
	if err != nil {
		return nil, fmt.Errorf("failed failed creating importable key: %v", err)
	}
	k, err = keyfile.ImportTPMKey(tpm, k, ownerauth)
	if err != nil {
		return nil, fmt.Errorf("failed turning imported key to loadable key: %v", err)
	}
	return &SSHTPMKey{k, nil, nil}, nil
}

func (k *SSHTPMKey) SSHPublicKey() (ssh.PublicKey, error) {
	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pubkey)
}

func (k *SSHTPMKey) Fingerprint() string {
	sshKey, err := k.SSHPublicKey()
	if err != nil {
		// This shouldn't happen
		panic("not a valid ssh key")
	}
	return ssh.FingerprintSHA256(sshKey)
}

func (k *SSHTPMKey) AuthorizedKey() []byte {
	sshKey, err := k.SSHPublicKey()
	if err != nil {
		// This shouldn't happen
		panic("not a valid ssh key")
	}
	authKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	return []byte(fmt.Sprintf("%s %s\n", authKey, k.Description))
}

func Decode(b []byte) (*SSHTPMKey, error) {
	k, err := keyfile.Decode(b)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k, nil, nil}, nil
}
