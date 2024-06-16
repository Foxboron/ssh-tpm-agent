package key

import (
	"errors"
	"fmt"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var (
	ErrOldKey = errors.New("old format on key")
)

type SSHTPMKey struct {
	*keyfile.TPMKey
}

func NewSSHTPMKey(tpm transport.TPMCloser, alg tpm2.TPMAlgID, bits int, ownerauth []byte, fn ...keyfile.TPMKeyOption) (*SSHTPMKey, error) {
	k, err := keyfile.NewLoadableKey(
		tpm, alg, bits, ownerauth, fn...,
	)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k}, nil
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
	return &SSHTPMKey{k}, nil
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

// ChangeAuth changes the object authn header to something else
// notice this changes the private blob inside the key in-place.
func ChangeAuth(tpm transport.TPMCloser, ownerPassword []byte, key *SSHTPMKey, oldpin, newpin []byte) (*SSHTPMKey, error) {
	var err error

	sess := keyfile.NewTPMSession(tpm)

	srkHandle, _, err := keyfile.CreateSRK(sess, tpm2.TPMRHOwner, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	defer utils.FlushHandle(tpm, srkHandle)

	handle, err := keyfile.LoadKeyWithParent(sess, *srkHandle, key.TPMKey)
	if err != nil {
		return nil, err
	}
	defer utils.FlushHandle(tpm, handle)

	if len(oldpin) != 0 {
		handle.Auth = tpm2.PasswordAuth(oldpin)
	}

	oca := tpm2.ObjectChangeAuth{
		ParentHandle: tpm2.NamedHandle{
			Handle: srkHandle.Handle,
			Name:   srkHandle.Name,
		},
		ObjectHandle: *handle,
		NewAuth: tpm2.TPM2BAuth{
			Buffer: newpin,
		},
	}
	rsp, err := oca.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("ObjectChangeAuth failed: %v", err)
	}

	key.Privkey = rsp.OutPrivate

	key.AddOptions(
		keyfile.WithPubkey(key.Pubkey),
		keyfile.WithPrivkey(key.Privkey),
		keyfile.WithDescription(key.Description),
		keyfile.WithUserAuth(newpin),
	)

	return key, nil
}

func Decode(b []byte) (*SSHTPMKey, error) {
	k, err := keyfile.Decode(b)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k}, nil
}
