package agent

import (
	"log"
	"net"
	"path"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/ssh/agent"
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

	ag := NewAgent(unixList,
		[]agent.ExtendedAgent{},
		// TPM Callback
		func() transport.TPMCloser {
			return tpm
		},
		// PIN Callback
		func(_ *key.Key) ([]byte, error) {
			return []byte(""), nil
		},
	)
	defer ag.Stop()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := agent.NewClient(conn)

	k, err := key.CreateKey(tpm, tpm2.TPMAlgECDSA, 256, []byte(""), []byte(""))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Extension(SSH_TPM_AGENT_ADD, key.EncodeKey(k))
	if err != nil {
		t.Fatal(err)
	}
}
