package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/foxboron/go-tpm-keyfiles/keyfile"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var (
	ErrOldKey = errors.New("old format on key")
)

type Key struct {
	*keyfile.TPMKey
}

func (k *Key) ecdsaPubKey() (*ecdsa.PublicKey, error) {
	ecc, err := k.TPMKey.Pubkey.Unique.ECC()
	if err != nil {
		return nil, err
	}

	eccdeets, err := k.TPMKey.Pubkey.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}

	var ecdsaKey *ecdsa.PublicKey

	switch eccdeets.CurveID {
	case tpm2.TPMECCNistP256:
		ecdsaKey = &ecdsa.PublicKey{Curve: elliptic.P256(),
			X: big.NewInt(0).SetBytes(ecc.X.Buffer),
			Y: big.NewInt(0).SetBytes(ecc.Y.Buffer),
		}
	case tpm2.TPMECCNistP384:
		ecdsaKey = &ecdsa.PublicKey{Curve: elliptic.P384(),
			X: big.NewInt(0).SetBytes(ecc.X.Buffer),
			Y: big.NewInt(0).SetBytes(ecc.Y.Buffer),
		}
	case tpm2.TPMECCNistP521:
		ecdsaKey = &ecdsa.PublicKey{Curve: elliptic.P521(),
			X: big.NewInt(0).SetBytes(ecc.X.Buffer),
			Y: big.NewInt(0).SetBytes(ecc.Y.Buffer),
		}
	}

	return ecdsaKey, nil
}

func (k *Key) rsaPubKey() (*rsa.PublicKey, error) {
	rsaDetail, err := k.TPMKey.Pubkey.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("failed getting rsa details: %v", err)
	}
	rsaUnique, err := k.TPMKey.Pubkey.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("failed getting unique rsa: %v", err)
	}

	return tpm2.RSAPub(rsaDetail, rsaUnique)
}

func (k *Key) PublicKey() (any, error) {
	switch k.TPMKey.KeyAlgo() {
	case tpm2.TPMAlgECC:
		return k.ecdsaPubKey()
	case tpm2.TPMAlgRSA:
		return k.rsaPubKey()
	}
	return nil, fmt.Errorf("no public key")
}

func (k *Key) SSHPublicKey() (ssh.PublicKey, error) {
	pubkey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pubkey)
}

func (k *Key) Fingerprint() string {
	sshKey, err := k.SSHPublicKey()
	if err != nil {
		// This shouldn't happen
		panic("not a valid ssh key")
	}
	return ssh.FingerprintSHA256(sshKey)
}

func (k *Key) AuthorizedKey() []byte {
	sshKey, err := k.SSHPublicKey()
	if err != nil {
		// This shouldn't happen
		panic("not a valid ssh key")
	}
	authKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	return []byte(fmt.Sprintf("%s %s\n", authKey, k.Description()))
}

func (k *Key) Encode() ([]byte, error) {
	return EncodeKey(k)
}

func UnmarshalKey(b []byte) (*Key, error) {
	key, err := keyfile.Parse(b)
	if err != nil {
		return nil, err
	}
	return &Key{key}, err
}

func MarshalKey(k *Key) ([]byte, error) {
	return keyfile.Marshal(k.TPMKey)
}

func EncodeKey(k *Key) ([]byte, error) {
	return keyfile.Encode(k.TPMKey)
}

func DecodeKey(pemBytes []byte) (*Key, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("not an armored key")
	}
	switch block.Type {
	case "TPM PRIVATE KEY":
		return nil, ErrOldKey
	case "TSS2 PRIVATE KEY":
		key, err := keyfile.Parse(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &Key{key}, nil
	default:
		return nil, fmt.Errorf("tpm-ssh: unsupported key type %q", block.Type)
	}
}

// Creates a Storage Key, or return the loaded storage key
func CreateSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

func createECCKey(ecc tpm2.TPMECCCurve, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: ecc,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
	})
}

func createRSAKey(bits tpm2.TPMKeyBits, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: bits,
			},
		),
	})
}

func CreateKey(tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin []byte, comment string) (*Key, error) {
	rsaBits := []int{2048}
	ecdsaBits := []int{256, 384, 521}

	supportedECCBitsizes := SupportedECCAlgorithms(tpm)

	switch keytype {
	case tpm2.TPMAlgECC:
		if bits == 0 {
			bits = ecdsaBits[0]
		}
		if !slices.Contains(ecdsaBits, bits) {
			return nil, errors.New("invalid ecdsa key length: valid length are 256, 384 or 512 bits")
		}
		if !slices.Contains(supportedECCBitsizes, bits) {
			return nil, fmt.Errorf("invalid ecdsa key length: TPM does not support %v bits", bits)
		}
	case tpm2.TPMAlgRSA:
		if bits == 0 {
			bits = rsaBits[0]
		}
		if !slices.Contains(rsaBits, bits) {
			return nil, errors.New("invalid rsa key length: only 2048 is supported")
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer utils.FlushHandle(tpm, srkHandle)

	var keyPublic tpm2.TPM2BPublic

	switch {
	case keytype == tpm2.TPMAlgECC && bits == 256:
		keyPublic = createECCKey(tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgECC && bits == 384:
		keyPublic = createECCKey(tpm2.TPMECCNistP384, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgECC && bits == 521:
		keyPublic = createECCKey(tpm2.TPMECCNistP521, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgRSA:
		keyPublic = createRSAKey(2048, tpm2.TPMAlgSHA256)
	}

	// Template for en ECC key for signing
	createKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic:     keyPublic,
	}

	emptyAuth := true
	if !bytes.Equal(pin, []byte("")) {
		createKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: pin,
				},
			},
		}
		emptyAuth = false
	}

	var createRsp *tpm2.CreateResponse
	createRsp, err = createKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	tpmkey, err := keyfile.NewLoadableKey(createRsp.OutPublic, createRsp.OutPrivate, srkHandle.Handle, emptyAuth)
	if err != nil {
		return nil, err
	}

	tpmkey.SetDescription(comment)

	return &Key{tpmkey}, nil
}

func ImportKey(tpm transport.TPMCloser, pk any, pin []byte, comment string) (*Key, error) {
	var public tpm2.TPMTPublic
	var sensitive tpm2.TPMTSensitive
	var unique tpm2.TPMUPublicID

	supportedECCBitsizes := SupportedECCAlgorithms(tpm)

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

	srkHandle, srkPublic, err := CreateSRK(tpm)
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

	// We need the size calcualted in the buffer, so we do this serialization dance
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

	tpmkey, err := keyfile.NewLoadableKey(pubbytes, importRsp.OutPrivate, srkHandle.Handle, emptyAuth)
	if err != nil {
		return nil, err
	}

	tpmkey.SetDescription(comment)

	return &Key{tpmkey}, nil
}

func LoadKeyWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, key *Key) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    key.TPMKey.Privkey,
		InPublic:     tpm2.New2B(key.TPMKey.Pubkey),
	}
	loadBlobRsp, err := loadBlobCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func LoadKey(tpm transport.TPMCloser, key *Key) (*tpm2.AuthHandle, error) {
	srkHandle, _, err := CreateSRK(tpm)
	if err != nil {
		return nil, err
	}

	defer utils.FlushHandle(tpm, srkHandle)

	return LoadKeyWithParent(tpm, *srkHandle, key)
}

func SupportedECCAlgorithms(tpm transport.TPMCloser) []int {
	var getCapRsp *tpm2.GetCapabilityResponse
	var supportedBitsizes []int

	eccCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapECCCurves,
		PropertyCount: 100,
	}
	getCapRsp, err := eccCapCmd.Execute(tpm)
	if err != nil {
		return []int{}
	}
	curves, err := getCapRsp.CapabilityData.Data.ECCCurves()
	if err != nil {
		return []int{}
	}
	for _, curve := range curves.ECCCurves {
		c, err := curve.Curve()
		// if we fail here we are dealing with an unsupported curve
		if err != nil {
			continue
		}
		supportedBitsizes = append(supportedBitsizes, c.Params().BitSize)
	}
	return supportedBitsizes
}
