package agent

import (
	"errors"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type AddedKey struct {
	PrivateKey           *keyfile.TPMKey
	Certificate          *ssh.Certificate
	Comment              string
	LifetimeSecs         uint32
	ConfirmBeforeUse     bool
	ConstraintExtensions []sshagent.ConstraintExtension
}

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

func ParseTPMKeyMsg(req []byte) (*AddedKey, error) {
	var k TPMKeyMsg

	var key *keyfile.TPMKey
	var err error

	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	if len(k.PrivateKey) != 0 {
		key, err = keyfile.Decode(k.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	addedKey := &AddedKey{PrivateKey: key}

	if len(k.CertBytes) != 0 {
		pubKey, err := ssh.ParsePublicKey(k.CertBytes)
		if err != nil {
			return nil, err
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("agent: bad tpm thing")
		}
		addedKey.Certificate = cert
	}

	if err := setConstraints(addedKey, k.Constraints); err != nil {
		return nil, err
	}

	return addedKey, nil
}
