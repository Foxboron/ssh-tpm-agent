package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"path"
	"testing"
	"time"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keytest"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func newSSHKey() ssh.Signer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		panic(err)
	}
	return signer
}

func setupServer(listener net.Listener, clientKey ssh.PublicKey) (hostkey ssh.PublicKey, msgSent chan bool) {
	hostSigner := newSSHKey()
	msgSent = make(chan bool)

	srvStart := make(chan bool)

	authorizedKeysMap := map[string]bool{}
	authorizedKeysMap[string(clientKey.Marshal())] = true

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	config.AddHostKey(hostSigner)

	go func() {
		close(srvStart)

		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal("failed to handshake: ", err)
		}

		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel: %v", err)
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {
					req.Reply(req.Type == "shell", nil)
				}
			}(requests)

			channel.Write([]byte("connected"))

			// Need to figure out something better
			time.Sleep(time.Millisecond * 100)
			close(msgSent)

			channel.Close()
		}
	}()

	// Waiting until the server has started
	<-srvStart

	return hostSigner.PublicKey(), msgSent
}

func runSSHAuth(t *testing.T, keytype tpm2.TPMAlgID, bits int, pin []byte, keyfn keytest.KeyFunc) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := keyfn(t, tpm, keytype, bits, pin, "")
	if err != nil {
		t.Fatalf("failed creating key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	hostkey, msgSent := setupServer(listener, *k.PublicKey)
	defer listener.Close()

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
		func(_ *key.SSHTPMKey) ([]byte, error) {
			return pin, nil
		},
	)
	defer ag.Stop()

	if err := ag.AddKey(k); err != nil {
		t.Fatalf("failed saving key: %v", err)
	}

	sshClient := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(ag.Signers),
		},
		HostKeyCallback: ssh.FixedHostKey(hostkey),
	}

	client, err := ssh.Dial("tcp", listener.Addr().String(), sshClient)
	if err != nil {
		t.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	session.Shell()

	var b bytes.Buffer
	session.Stdout = &b

	<-msgSent
	if b.String() != "connected" {
		t.Fatalf("failed to connect")
	}
}

func TestSSHAuth(t *testing.T) {
	for _, c := range []struct {
		name string
		alg  tpm2.TPMAlgID
		bits int
	}{
		{
			"ecdsa p256 - agent",
			tpm2.TPMAlgECC,
			256,
		},
		{
			"ecdsa p384 - agent",
			tpm2.TPMAlgECC,
			384,
		},
		{
			"ecdsa p521 - agent",
			tpm2.TPMAlgECC,
			521,
		},
		{
			"rsa - agent",
			tpm2.TPMAlgRSA,
			2048,
		},
	} {
		t.Run(c.name+" - tpm key", func(t *testing.T) {
			runSSHAuth(t, c.alg, c.bits, []byte(""), keytest.MkKey)
		})
		t.Run(c.name+" - imported key", func(t *testing.T) {
			runSSHAuth(t, c.alg, c.bits, []byte(""), keytest.MkImportableKey)
		})
	}
}
