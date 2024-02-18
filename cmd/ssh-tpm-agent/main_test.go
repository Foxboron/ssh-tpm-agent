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

func runSSHAuth(t *testing.T, keytype tpm2.TPMAlgID, bits int) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}

	k, err := key.CreateKey(tpm, keytype, bits, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("failed creating key: %v", err)
	}
	clientKey, err := k.SSHPublicKey()
	if err != nil {
		t.Fatalf("failed getting ssh public key")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	hostkey, msgSent := setupServer(listener, clientKey)
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
		func() transport.TPMCloser {
			return tpm
		},
		// PIN Callback
		func(_ *key.Key) ([]byte, error) {
			return []byte(""), nil
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
	t.Run("ecdsa p256 - agent", func(t *testing.T) {
		runSSHAuth(t, tpm2.TPMAlgECDSA, 256)
	})
	t.Run("rsa - agent", func(t *testing.T) {
		runSSHAuth(t, tpm2.TPMAlgRSA, 2048)
	})
	t.Run("ecdsa p384 - agent", func(t *testing.T) {
		runSSHAuth(t, tpm2.TPMAlgECDSA, 384)
	})
	t.Run("ecdsa p521 - agent", func(t *testing.T) {
		runSSHAuth(t, tpm2.TPMAlgECDSA, 521)
	})
}
