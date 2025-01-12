package key

import (
	"errors"
	"fmt"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrOldKey = errors.New("old format on key")
)

// SSHTPMKey is a wrapper for TPMKey implementing the ssh.PublicKey specific parts
type SSHTPMKey struct {
	*keyfile.TPMKey
	PublicKey   *ssh.PublicKey
	Certificate *ssh.Certificate
}

func WrapTPMKey(k *keyfile.TPMKey) (*SSHTPMKey, error) {
	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	sshkey, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k, &sshkey, nil}, nil
}

func NewSSHTPMKey(tpm transport.TPMCloser, alg tpm2.TPMAlgID, bits int, ownerauth []byte, fn ...keyfile.TPMKeyOption) (*SSHTPMKey, error) {
	k, err := keyfile.NewLoadableKey(
		tpm, alg, bits, ownerauth, fn...,
	)
	if err != nil {
		return nil, err
	}
	return WrapTPMKey(k)
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
	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	sshkey, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k, &sshkey, nil}, nil
}

func (k *SSHTPMKey) Fingerprint() string {
	return ssh.FingerprintSHA256(*k.PublicKey)
}

func (k *SSHTPMKey) AuthorizedKey() []byte {
	return []byte(fmt.Sprintf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(*k.PublicKey))), k.Description))
}

func (k *SSHTPMKey) AgentKey() *agent.Key {
	if k.Certificate != nil {
		return &agent.Key{
			Format:  k.Certificate.Type(),
			Blob:    k.Certificate.Marshal(),
			Comment: k.Description,
		}
	}

	return &agent.Key{
		Format:  (*k.PublicKey).Type(),
		Blob:    (*k.PublicKey).Marshal(),
		Comment: k.Description,
	}
}

func Decode(b []byte) (*SSHTPMKey, error) {
	k, err := keyfile.Decode(b)
	if err != nil {
		return nil, err
	}
	return WrapTPMKey(k)
}
