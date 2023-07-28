package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/signer"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Return XDG_DATA_HOME or $HOME/.local/share
func getDataHome() string {
	if s, ok := os.LookupEnv("XDG_DATA_HOME"); ok {
		return s
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}

	return path.Join(dirname, ".local/share")
}

func getAgentStorage() string {
	return path.Join(getDataHome(), "ssh-tpm-agent")
}

func SaveKey(k *key.Key) error {
	os.MkdirAll(getAgentStorage(), 0700)
	return os.WriteFile(path.Join(getAgentStorage(), "ssh.key"), key.MarshalKey(k), 0600)
}

var ErrOperationUnsupported = errors.New("operation unsupported")

type Agent struct {
	mu       sync.Mutex
	tpm      func() transport.TPMCloser
	pin      func(*key.Key) ([]byte, error)
	listener net.Listener
	quit     chan interface{}
	wg       sync.WaitGroup
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) RemoveAll() error {
	return a.Close()
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}

func (a *Agent) Close() error {
	a.Stop()
	return nil
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	b, err := os.ReadFile(path.Join(getAgentStorage(), "ssh.key"))
	if err != nil {
		return nil, err
	}
	k, err := key.UnmarshalKey(b)
	if err != nil {
		return nil, err
	}
	s, err := ssh.NewSignerFromSigner(signer.NewTPMSigner(k, a.tpm, a.pin))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	return []ssh.Signer{s}, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signers()
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(path.Join(getAgentStorage(), "ssh.key"))
	if err != nil {
		return nil, err
	}

	k, err := key.UnmarshalKey(b)
	if err != nil {
		return nil, err
	}

	pk, err := k.SSHPublicKey()
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format: pk.Type(),
		Blob:   pk.Marshal(),
	}}, nil
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	signers, err := a.signers()
	if err != nil {
		return nil, err
	}

	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, key.Type())
	}

	return nil, fmt.Errorf("no private keys match the requested public key")
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func (a *Agent) Wait() {
	a.wg.Wait()
}

func (a *Agent) Stop() {
	close(a.quit)
	a.listener.Close()
	a.wg.Wait()
}

func (a *Agent) serve() {
	defer a.wg.Done()
	for {
		c, err := a.listener.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			select {
			case <-a.quit:
				return
			default:
				log.Fatalln("Failed to accept connections:", err)
			}
		}
		a.wg.Add(1)
		go func() {
			a.serveConn(c)
			a.wg.Done()
		}()
	}
}

func NewAgent(socketPath string, tpmFetch func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *Agent {
	a := &Agent{
		tpm:  tpmFetch,
		pin:  pin,
		quit: make(chan interface{}),
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	a.listener = l
	a.wg.Add(1)
	go a.serve()
	return a
}

func execAgent(socketPath string, tpmFetch func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *Agent {
	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
	a := NewAgent(socketPath, tpmFetch, pin)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Stop()
		}
	}()

	return a
}

func RunAgent(socketPath string, tpmFetch func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: ssh-tpm-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using a systemd service.")
	}

	a := execAgent(socketPath, tpmFetch, pin)
	a.Wait()
}
