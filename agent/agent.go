package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/signer"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slog"
)

var ErrOperationUnsupported = errors.New("operation unsupported")

var SSH_TPM_AGENT_ADD = "tpm-add-key"

type Agent struct {
	mu       sync.Mutex
	tpm      func() transport.TPMCloser
	pin      func(*key.Key) ([]byte, error)
	listener *net.UnixListener
	quit     chan interface{}
	wg       sync.WaitGroup
	keys     map[string]*key.Key
	agents   []agent.ExtendedAgent
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	slog.Debug("called extensions")
	switch extensionType {
	case SSH_TPM_AGENT_ADD:
		slog.Debug("runnning extension", slog.String("type", extensionType))
		return a.AddTPMKey(contents)
	}
	return nil, agent.ErrExtensionUnsupported
}

func (a *Agent) AddTPMKey(contents []byte) ([]byte, error) {
	slog.Debug("called addtpmkey")
	a.mu.Lock()
	defer a.mu.Unlock()
	k, err := key.DecodeKey(contents)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	a.keys[k.Fingerprint()] = k

	return []byte(""), nil
}

func (a *Agent) Close() error {
	slog.Debug("called close")
	a.Stop()
	return nil
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for _, agent := range a.agents {
		l, err := agent.Signers()
		if err != nil {
			slog.Info("failed getting Signers from agent", slog.String("error", err.Error()))
			continue
		}
		signers = append(signers, l...)
	}

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
	slog.Debug("called signers")
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signers()
}

func (a *Agent) List() ([]*agent.Key, error) {
	slog.Debug("called list")
	var agentKeys []*agent.Key

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, agent := range a.agents {
		l, err := agent.List()
		if err != nil {
			slog.Info("failed getting list from agent", slog.String("error", err.Error()))
			continue
		}
		agentKeys = append(agentKeys, l...)
	}

	for _, k := range a.keys {
		pk, err := k.SSHPublicKey()
		if err != nil {
			return nil, err
		}

		agentKeys = append(agentKeys, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: string(k.Comment),
		})
	}
	return agentKeys, nil
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	slog.Debug("called signwithflags")
	a.mu.Lock()
	defer a.mu.Unlock()
	signers, err := a.signers()
	if err != nil {
		return nil, err
	}

	alg := key.Type()
	switch {
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
		alg = ssh.KeyAlgoRSASHA256
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
		alg = ssh.KeyAlgoRSASHA512
	}

	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}

	slog.Debug("trying to sign as proxy...")
	for _, agent := range a.agents {
		signers, err := agent.Signers()
		if err != nil {
			slog.Info("failed getting signers from agent", slog.String("error", err.Error()))
			continue
		}
		for _, s := range signers {
			if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
				continue
			}
			return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
		}
	}

	return nil, fmt.Errorf("no private keys match the requested public key")
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	slog.Debug("called sign")
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		slog.Info("Agent client connection ended unsuccessfully", slog.String("error", err.Error()))
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
		c, err := a.listener.AcceptUnix()
		if err != nil {
			type temporary interface {
				Temporary() bool
				Error() string
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				slog.Info("Temporary Accept failure, sleeping 1s", slog.String("error", err.Error()))
				time.Sleep(1 * time.Second)
				continue
			}
			select {
			case <-a.quit:
				return
			default:
				slog.Error("Failed to accept connections", slog.String("error", err.Error()))
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
	slog.Debug("called addkey")
	a.keys[k.Fingerprint()] = k
	return nil
}

func (a *Agent) LoadKeys(keyDir string) error {
	slog.Debug("called loadkeys")
	a.mu.Lock()
	defer a.mu.Unlock()
	keys, err := LoadKeys(keyDir)
	if err != nil {
		return err
	}

	a.keys = keys
	return nil
}

// Unsupported functions
func (a *Agent) Add(key agent.AddedKey) error {
	slog.Debug("called add")
	return ErrOperationUnsupported
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	slog.Debug("called remove")
	return ErrOperationUnsupported
}

func (a *Agent) RemoveAll() error {
	slog.Debug("called removeall")
	return a.Close()
}

func (a *Agent) Lock(passphrase []byte) error {
	slog.Debug("called lock")
	return ErrOperationUnsupported
}

func (a *Agent) Unlock(passphrase []byte) error {
	slog.Debug("called unlock")
	return ErrOperationUnsupported
}

func LoadKeys(keyDir string) (map[string]*key.Key, error) {
	keys := map[string]*key.Key{}
	err := filepath.WalkDir(keyDir,
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
				slog.Debug("not a TPM-sealed key", slog.String("key_path", path), slog.String("error", err.Error()))
				return nil
			}
			keys[k.Fingerprint()] = k
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func NewAgent(listener *net.UnixListener, agents []agent.ExtendedAgent, tpmFetch func() transport.TPMCloser, pin func(*key.Key) ([]byte, error)) *Agent {
	a := &Agent{
		agents:   agents,
		tpm:      tpmFetch,
		listener: listener,
		pin:      pin,
		quit:     make(chan interface{}),
		keys:     make(map[string]*key.Key),
	}

	a.wg.Add(1)
	go a.serve()
	return a
}
