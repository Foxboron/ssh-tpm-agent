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
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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

func DoesHandleExist(tpm transport.TPMCloser, handle tpm2.TPMHandle) (bool, error) {
	capability := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(handle),
		PropertyCount: 1,
	}

	rsp, err := capability.Execute(tpm)
	if err != nil {
		return false, fmt.Errorf("failed getting capability: %v", err)
	}

	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		return false, fmt.Errorf("failed getting handles: %v", err)
	}

	if len(handles.Handle) == 0 || handles.Handle[0] != handle {
		return false, nil
	}

	return true, nil
}

func PersistSRK(tpm transport.TPMCloser, ownerPassword []byte, authHandle *tpm2.AuthHandle, handle tpm2.TPMHandle) error {
	evict := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPassword),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: authHandle.Handle,
			Name:   authHandle.Name,
		},
		PersistentHandle: handle,
	}

	_, err := evict.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed persisting primary key: %v", err)
	}

	return nil
}

// ReadSRK Loads a persistent Storage Key
func ReadSRK(tpm transport.TPMCloser, handle tpm2.TPMHandle) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.ReadPublic{
		ObjectHandle: handle,
	}

	var rsp *tpm2.ReadPublicResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: handle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

// Creates a Storage Key, or return the loaded storage key
func CreateSRK(tpm transport.TPMCloser, ownerPassword []byte) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(ownerPassword),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(""),
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

func GetOrCreateSRK(tpm transport.TPMCloser, handle tpm2.TPMHandle, ownerPassword []byte) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	if handle == 0x0 {
		return CreateSRK(tpm, ownerPassword)
	} else {
		doesHandleExist, err := DoesHandleExist(tpm, handle)
		if err != nil {
			return nil, nil, err
		}

		if doesHandleExist {
			return ReadSRK(tpm, handle)
		} else {
			authHandle, public, err := CreateSRK(tpm, ownerPassword)
			if err != nil {
				return nil, nil, err
			}

			err = PersistSRK(tpm, ownerPassword, authHandle, handle)
			if err != nil {
				return nil, nil, err
			}

			return authHandle, public, nil
		}
	}
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

func CreateKey(tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, ownerPassword []byte, srkHandle tpm2.TPMHandle, pin []byte, comment string) (*Key, error) {
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

	srkAuthHandle, srkPublic, err := GetOrCreateSRK(tpm, srkHandle, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer utils.FlushHandle(tpm, srkAuthHandle)

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
		ParentHandle: srkAuthHandle,
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

	createRsp, err := createKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkAuthHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	tpmkey, err := keyfile.NewLoadableKey(createRsp.OutPublic, createRsp.OutPrivate, srkAuthHandle.Handle, emptyAuth)
	if err != nil {
		return nil, err
	}

	tpmkey.SetDescription(comment)

	return &Key{tpmkey}, nil
}

func ImportKey(tpm transport.TPMCloser, ownerPassword []byte, srkHandle tpm2.TPMHandle, pk any, pin []byte, comment string) (*Key, error) {
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

	srkAuthHandle, srkPublic, err := GetOrCreateSRK(tpm, srkHandle, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer utils.FlushHandle(tpm, srkAuthHandle)

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
		ParentHandle: srkAuthHandle,
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
		ObjectPublic: pubbytes,
	}

	var importRsp *tpm2.ImportResponse
	importRsp, err = importCmd.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkAuthHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	tpmkey, err := keyfile.NewLoadableKey(pubbytes, importRsp.OutPrivate, srkAuthHandle.Handle, emptyAuth)
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

func LoadKey(tpm transport.TPMCloser, ownerPassword []byte, srkHandle tpm2.TPMHandle, key *Key) (*tpm2.AuthHandle, error) {
	srkAuthHandle, _, err := GetOrCreateSRK(tpm, srkHandle, ownerPassword)
	if err != nil {
		return nil, err
	}

	defer utils.FlushHandle(tpm, srkAuthHandle)

	return LoadKeyWithParent(tpm, *srkAuthHandle, key)
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

// from crypto/ecdsa
func encodeSignature(r, s []byte) ([]byte, error) {
	addASN1IntBytes := func(b *cryptobyte.Builder, bytes []byte) {
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

func Sign(tpm transport.TPMCloser, ownerPassword []byte, srkHandle tpm2.TPMHandle, key *Key, digest []byte, auth []byte, digestalg tpm2.TPMAlgID) ([]byte, error) {
	var digestlength int

	switch digestalg {
	case tpm2.TPMAlgSHA256:
		digestlength = 32
	case tpm2.TPMAlgSHA384:
		digestlength = 48
	case tpm2.TPMAlgSHA512:
		digestlength = 64
	}

	if len(digest) != digestlength {
		return nil, fmt.Errorf("incorrect checksum length. expected %v got %v", digestlength, len(digest))
	}

	srkAuthHandle, srkPublic, err := GetOrCreateSRK(tpm, srkHandle, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	defer utils.FlushHandle(tpm, srkAuthHandle)

	handle, err := LoadKeyWithParent(tpm, *srkAuthHandle, key)
	if err != nil {
		return nil, err
	}
	defer utils.FlushHandle(tpm, handle)

	if key.TPMKey.HasAuth() {
		handle.Auth = tpm2.PasswordAuth(auth)
	}

	var sigscheme tpm2.TPMTSigScheme
	switch key.TPMKey.KeyAlgo() {
	case tpm2.TPMAlgECC:
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
			tpm2.Salted(srkAuthHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	switch key.TPMKey.KeyAlgo() {
	case tpm2.TPMAlgECC:
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

// ChangeAuth changes the object authn header to something else
// notice this changes the private blob inside the key in-place.
func ChangeAuth(tpm transport.TPMCloser, ownerPassword []byte, srkHandle tpm2.TPMHandle, key *Key, oldpin, newpin []byte) (*Key, error) {
	var err error

	srkAuthHandle, _, err := GetOrCreateSRK(tpm, srkHandle, ownerPassword)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	defer utils.FlushHandle(tpm, srkAuthHandle)

	handle, err := LoadKeyWithParent(tpm, *srkAuthHandle, key)
	if err != nil {
		return nil, err
	}
	defer utils.FlushHandle(tpm, handle)

	if len(oldpin) != 0 {
		handle.Auth = tpm2.PasswordAuth(oldpin)
	}

	oca := tpm2.ObjectChangeAuth{
		ParentHandle: tpm2.NamedHandle{
			Handle: srkAuthHandle.Handle,
			Name:   srkAuthHandle.Name,
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
	var emptyAuth bool
	if len(newpin) == 0 {
		emptyAuth = true
	}

	newkey, err := keyfile.NewLoadableKey(tpm2.New2B(key.Pubkey), key.Privkey, key.Parent, emptyAuth)
	if err != nil {
		return nil, err
	}
	return &Key{newkey}, nil
}
