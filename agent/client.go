package agent

import (
	"errors"
	"math"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// type AddedKey struct {
// 	PrivateKey           *keyfile.TPMKey
// 	Certificate          *ssh.Certificate
// 	Comment              string
// 	LifetimeSecs         uint32
// 	ConfirmBeforeUse     bool
// 	ConstraintExtensions []sshagent.ConstraintExtension
// }

type TPMKeyMsg struct {
	Type        string `sshtype:"17|25"`
	PrivateKey  []byte
	CertBytes   []byte
	Constraints []byte `ssh:"rest"`
}

func MarshalTPMKeyMsg(cert *sshagent.AddedKey) []byte {
	var req []byte
	var constraints []byte

	if secs := cert.LifetimeSecs; secs != 0 {
		constraints = append(constraints, ssh.Marshal(constrainLifetimeAgentMsg{secs})...)
	}

	if cert.ConfirmBeforeUse {
		constraints = append(constraints, agentConstrainConfirm)
	}

	var certBytes []byte
	if cert.Certificate != nil {
		certBytes = cert.Certificate.Marshal()
	}

	switch k := cert.PrivateKey.(type) {
	case *keyfile.TPMKey:
		req = ssh.Marshal(TPMKeyMsg{
			Type:        "TPMKEY",
			PrivateKey:  k.Bytes(),
			CertBytes:   certBytes,
			Constraints: constraints,
		})
	case *key.SSHTPMKey:
		req = ssh.Marshal(TPMKeyMsg{
			Type:        "TPMKEY",
			PrivateKey:  k.Bytes(),
			CertBytes:   certBytes,
			Constraints: constraints,
		})

	}
	return req
}

// certExpiryGrace is how long past its ValidBefore the agent keeps a
// certificate added with CertLifetime: CERT_EXPIRY_GRACE of ssh-add(1).
const certExpiryGrace = 5 * 60

// CertLifetime is the lifetime constraint, in seconds, that ssh-add(1) adds a
// certificate with, so the agent deletes it shortly after it expires: none
// (0) for a certificate that never expires. expired is set for a certificate
// already past that, which ssh-add ignores.
func CertLifetime(cert *ssh.Certificate, now time.Time) (secs uint32, expired bool) {
	if cert.ValidBefore >= ssh.CertTimeInfinity-certExpiryGrace {
		return 0, false
	}
	end := cert.ValidBefore + certExpiryGrace
	n := uint64(max(now.Unix(), 0))
	if n > end {
		return 0, true
	}
	// 0 would be no lifetime at all
	return uint32(max(min(end-n, math.MaxInt32), 1)), false
}

func ParseTPMKeyMsg(req []byte) (*key.SSHTPMKey, error) {
	var (
		k      TPMKeyMsg
		tpmkey *key.SSHTPMKey
		err    error
	)

	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	if len(k.PrivateKey) != 0 {
		tpmkey, err = key.Decode(k.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	if tpmkey != nil && len(k.Constraints) != 0 {
		if err := setConstraints(tpmkey, k.Constraints); err != nil {
			return nil, err
		}
	}

	if len(k.CertBytes) != 0 {
		pubKey, err := ssh.ParsePublicKey(k.CertBytes)
		if err != nil {
			return nil, err
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("agent: bad tpm thing")
		}
		tpmkey.Certificate = cert
	}

	return tpmkey, nil
}
