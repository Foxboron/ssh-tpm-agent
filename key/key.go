package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
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

func ImportKey(tpm transport.TPMCloser, ownerPassword []byte, pk any, pin []byte, comment string) (*SSHTPMKey, error) {
	var public tpm2.TPMTPublic
	var sensitive tpm2.TPMTSensitive
	var unique tpm2.TPMUPublicID

	supportedECCBitsizes := keyfile.SupportedECCAlgorithms(tpm)

	switch p := pk.(type) {
	case ecdsa.PrivateKey:
		var curveid tpm2.TPMECCCurve

		if !slices.Contains(supportedECCBitsizes, p.Params().BitSize) {
			return nil, fmt.Errorf("invalid ecdsa key length: TPM does not support %v bits", p.Params().BitSize)
		}

		switch p.Params().BitSize {
		case 256:
			curveid = tpm2.TPMECCNistP256
		case 384:
			curveid = tpm2.TPMECCNistP384
		case 521:
			curveid = tpm2.TPMECCNistP521
		}

		// Prepare ECC key for importing
		sensitive = tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgECC,
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgECC,
				&tpm2.TPM2BECCParameter{Buffer: p.D.FillBytes(make([]byte, len(p.D.Bytes())))},
			),
		}

		unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: p.X.FillBytes(make([]byte, len(p.X.Bytes()))),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: p.Y.FillBytes(make([]byte, len(p.Y.Bytes()))),
				},
			},
		)

		public = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:  true,
				UserWithAuth: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: curveid,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
			Unique: unique,
		}

	case rsa.PrivateKey:
		// TODO: Reject larger keys than 2048

		// Prepare RSA key for importing
		sensitive = tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgRSA,
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPrivateKeyRSA{Buffer: p.Primes[0].Bytes()},
			),
		}

		unique = tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: p.N.Bytes()},
		)

		public = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:  true,
				UserWithAuth: true,
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
			Unique: unique,
		}

	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	sess := keyfile.NewTPMSession(tpm)

	srkHandle, srkPublic, err := keyfile.CreateSRK(sess, tpm2.TPMRHOwner, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer utils.FlushHandle(tpm, srkHandle)

	emptyAuth := true
	if !bytes.Equal(pin, []byte("")) {
		sensitive.AuthValue = tpm2.TPM2BAuth{
			Buffer: pin,
		}
		emptyAuth = false
	}

	// We need the size calculated in the buffer, so we do this serialization dance
	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: tpm2.Marshal(sensitive)})

	pubbytes := tpm2.New2B(public)

	importCmd := tpm2.Import{
		ParentHandle: srkHandle,
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
		ObjectPublic: pubbytes,
	}

	var importRsp *tpm2.ImportResponse
	importRsp, err = importCmd.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	k := keyfile.NewTPMKey(
		keyfile.WithKeytype(keyfile.OIDLoadableKey),
		keyfile.WithPubkey(pubbytes),
		keyfile.WithPrivkey(importRsp.OutPrivate),
		keyfile.WithDescription(comment),
	)
	k.EmptyAuth = emptyAuth

	return &SSHTPMKey{k}, nil
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

	k := keyfile.NewTPMKey(
		keyfile.WithPubkey(key.Pubkey),
		keyfile.WithPrivkey(key.Privkey),
		keyfile.WithDescription(key.Description),
		keyfile.WithUserAuth(newpin),
	)

	return &SSHTPMKey{k}, nil
}

func Decode(b []byte) (*SSHTPMKey, error) {
	k, err := keyfile.Decode(b)
	if err != nil {
		return nil, err
	}
	return &SSHTPMKey{k}, nil
}
