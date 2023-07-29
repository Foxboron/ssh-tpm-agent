package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
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

var ErrOperationUnsupported = errors.New("operation unsupported")

type Agent struct {
	mu       sync.Mutex
	tpm      func() transport.TPMCloser
	pin      func(*key.Key) ([]byte, error)
	listener net.Listener
	quit     chan interface{}
	wg       sync.WaitGroup
	keys     map[string]*key.Key
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
	var signers []ssh.Signer
	for _, k := range a.keys {
		s, err := ssh.NewSignerFromSigner(signer.NewTPMSigner(k, a.tpm, a.pin))
		if err != nil {
			return nil, fmt.Errorf("failed to prepare signer: %w", err)
		}
		signers = append(signers, s)
	}
	return signers, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signers()
}

func (a *Agent) List() ([]*agent.Key, error) {
	var agentKeys []*agent.Key

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, k := range a.keys {
		pk, err := k.SSHPublicKey()
		if err != nil {
			return nil, err
		}

		agentKeys = append(agentKeys, &agent.Key{
			Format: pk.Type(),
			Blob:   pk.Marshal(),
		})
	}
	return agentKeys, nil
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

func (a *Agent) AddKey(k *key.Key) error {
	sshpubkey, err := k.SSHPublicKey()
	if err != nil {
		return err
	}
	a.keys[ssh.FingerprintSHA256(sshpubkey)] = k
	return nil
}

func (a *Agent) LoadKeys() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys, err := LoadKeys()
	if err != nil {
		return err
	}

	a.keys = keys
	return nil
}

func GetSSHDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}
	return path.Join(dirname, ".ssh")
}

func LoadKeys() (map[string]*key.Key, error) {
	keys := map[string]*key.Key{}
	err := filepath.WalkDir(GetSSHDir(),
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, "tpm") {
				return nil
			}
			f, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed reading %s", path)
			}
			k, err := key.DecodeKey(f)
			if err != nil {
				return fmt.Errorf("%s not a TPM sealed key: %v", path, err)
			}
			sshpubkey, err := k.SSHPublicKey()
			if err != nil {
				return fmt.Errorf("%s can't read ssh public key from TPM public: %v", path, err)
			}
			keys[ssh.FingerprintSHA256(sshpubkey)] = k
			return nil
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	return keys, nil
}

func NewAgent(socketPath string, tpmFetch func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *Agent {
	a := &Agent{
		tpm:  tpmFetch,
		pin:  pin,
		quit: make(chan interface{}),
		keys: make(map[string]*key.Key),
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
	log.Printf("Listening on %v\n", socketPath);
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

	//TODO: Maybe we should allow people to not auto-load keys
	a.LoadKeys()

	a.Wait()
}
