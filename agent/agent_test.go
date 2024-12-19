package agent_test

import (
	"crypto/elliptic"
	"errors"
	"log"
	"net"
	"path"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keytest"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestAddKey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	socket := path.Join(t.TempDir(), "socket")
	unixList, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})

	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}
	defer unixList.Close()

	ag := agent.NewAgent(unixList,
		[]sshagent.ExtendedAgent{},
		// TPM Callback
		func() transport.TPMCloser { return tpm },
		// Owner password
		func() ([]byte, error) { return []byte(""), nil },
		// PIN Callback
		func(_ *key.SSHTPMKey) ([]byte, error) { return []byte(""), nil },
	)
	defer ag.Stop()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := sshagent.NewClient(conn)

	k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}

	addedkey := sshagent.AddedKey{
		PrivateKey:  k,
		Certificate: nil,
		Comment:     k.Description,
	}

	_, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&addedkey))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigning(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ca := keytest.MkECDSA(t, elliptic.P256())
	for _, c := range []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		wanterr error
	}{
		{
			text: "sign key",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
			f:    keytest.MkKey,
		},
		{
			text: "sign key cert",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
			f:    keytest.MkCertificate(t, &ca),
		},
	} {

		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			ag := keytest.NewTestAgent(t, tpm)
			defer ag.Stop()

			if err := ag.AddKey(k); err != nil {
				t.Fatalf("failed saving key: %v", err)
			}

			// Shim the certificate if there is one
			var sshkey ssh.PublicKey
			if k.Certificate != nil {
				sshkey = k.Certificate
			} else {
				sshkey, err = k.SSHPublicKey()
				if err != nil {
					t.Fatalf("failed getting ssh public key")
				}
			}

			_, err = ag.Sign(sshkey, []byte("test"))
			if !errors.Is(err, c.wanterr) {
				t.Fatalf("failed signing: %v", err)
			}

		})
	}
}
