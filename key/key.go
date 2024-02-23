package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

// We need to know if the TPM handle has a pin set
type PINStatus uint8

const (
	NoPIN PINStatus = iota
	HasPIN
)

func (p PINStatus) String() string {
	switch p {
	case NoPIN:
		return "NoPIN"
	case HasPIN:
		return "HasPIN"
	}
	return "Not a PINStatus"
}

type Key struct {
	Version uint8
	PIN     PINStatus
	Type    tpm2.TPMAlgID
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
	Comment []byte
}

func (k *Key) ecdsaPubKey() (*ecdsa.PublicKey, error) {
	c := tpm2.BytesAs2B[tpm2.TPMTPublic](k.Public.Bytes())
	pub, err := c.Contents()
	if err != nil {
		return nil, err
	}
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	eccdeets, err := pub.Parameters.ECCDetail()
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
	pub, err := k.Public.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed getting content: %v", err)
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("failed getting rsa details: %v", err)
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("failed getting unique rsa: %v", err)
	}

	return tpm2.RSAPub(rsaDetail, rsaUnique)
}

func (k *Key) PublicKey() (any, error) {
	switch k.Type {
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
	return []byte(fmt.Sprintf("%s %s\n", authKey, string(k.Comment)))
}

func (k *Key) Encode() []byte {
	return EncodeKey(k)
}

func UnmarshalKey(b []byte) (*Key, error) {
	var key Key
	var comment []byte

	r := bytes.NewBuffer(b)

	for _, k := range []interface{}{
		&key.Version,
		&key.PIN,
		&key.Type,
	} {
		if err := binary.Read(r, binary.BigEndian, k); err != nil {
			return nil, fmt.Errorf("failed unmarshal of fields: %v", err)
		}
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](r.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed unmarshal of TPM2BPublic: %v", err)
	}

	// The TPM byte blob + the two bytes for the blob length
	bLength := len(public.Bytes()) + 2

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](r.Bytes()[bLength:])
	if err != nil {
		return nil, fmt.Errorf("failed unmarshal of TPM2BPrivate: %v", err)
	}

	// The TPM byte blob + the two bytes for the blob length
	bLength += len(private.Buffer) + 2

	// Advance the reader with the TPM blobs we've read
	r.Next(bLength)

	if r.Len() != 0 {
		comment = make([]byte, r.Len())
		r.Read(comment)
	}

	key.Public = *public
	key.Private = *private
	key.Comment = comment

	return &key, err
}

func MarshalKey(k *Key) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, k.Version)
	binary.Write(&b, binary.BigEndian, k.PIN)
	binary.Write(&b, binary.BigEndian, k.Type)

	var pub []byte
	pub = append(pub, tpm2.Marshal(k.Public)...)
	pub = append(pub, tpm2.Marshal(k.Private)...)
	pub = append(pub, k.Comment...)
	b.Write(pub)

	return b.Bytes()
}

var (
	keyType = "TPM PRIVATE KEY"
)

func EncodeKey(k *Key) []byte {
	data := MarshalKey(k)

	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{
		Type:  keyType,
		Bytes: data,
	})
	return buf.Bytes()
}

func DecodeKey(pemBytes []byte) (*Key, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("not an armored key")
	}
	switch block.Type {
	case "TPM PRIVATE KEY":
		return UnmarshalKey(block.Bytes)
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

func CreateKey(tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, pin, comment []byte) (*Key, error) {
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

	pinstatus := NoPIN

	if !bytes.Equal(pin, []byte("")) {
		createKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: pin,
				},
			},
		}
		pinstatus = HasPIN
	}

	var createRsp *tpm2.CreateResponse
	createRsp, err = createKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	return &Key{
		Version: 1,
		PIN:     pinstatus,
		Type:    keytype,
		Private: createRsp.OutPrivate,
		Public:  createRsp.OutPublic,
		Comment: comment,
	}, nil
}

func ImportKey(tpm transport.TPMCloser, pk any, pin, comment []byte) (*Key, error) {
	var public tpm2.TPMTPublic
	var sensitive tpm2.TPMTSensitive
	var unique tpm2.TPMUPublicID

	supportedECCBitsizes := SupportedECCAlgorithms(tpm)

	var keytype tpm2.TPMAlgID

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

		keytype = tpm2.TPMAlgECC

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

		keytype = tpm2.TPMAlgRSA

	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer utils.FlushHandle(tpm, srkHandle)

	pinstatus := NoPIN

	if !bytes.Equal(pin, []byte("")) {
		sensitive.AuthValue = tpm2.TPM2BAuth{
			Buffer: pin,
		}
		pinstatus = HasPIN
	}

	// We need the size calcualted in the buffer, so we do this serialization dance
	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: tpm2.Marshal(sensitive)})

	importCmd := tpm2.Import{
		ParentHandle: srkHandle,
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
		ObjectPublic: tpm2.New2B(public),
	}

	var importRsp *tpm2.ImportResponse
	importRsp, err = importCmd.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	return &Key{
		Version: 1,
		PIN:     pinstatus,
		Private: importRsp.OutPrivate,
		Public:  importCmd.ObjectPublic,
		Type:    keytype,
		Comment: comment,
	}, nil
}

func LoadKeyWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, key *Key) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    key.Private,
		InPublic:     key.Public,
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
