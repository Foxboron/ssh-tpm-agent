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
	"slices"
	"strings"
	"sync"
	"time"

	"log/slog"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/signer"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrOperationUnsupported = errors.New("operation unsupported")

var SSH_TPM_AGENT_ADD = "tpm-add-key"

type Agent struct {
	mu       sync.Mutex
	tpm      func() transport.TPMCloser
	op       func() ([]byte, error)
	pin      func(*key.SSHTPMKey) ([]byte, error)
	listener *net.UnixListener
	quit     chan interface{}
	wg       sync.WaitGroup
	keys     []*key.SSHTPMKey
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

func (a *Agent) AddTPMKey(addedkey []byte) ([]byte, error) {
	slog.Debug("called addtpmkey")
	a.mu.Lock()
	defer a.mu.Unlock()

	addkey, err := ParseTPMKeyMsg(addedkey)
	if err != nil {
		return nil, err
	}

	k := &key.SSHTPMKey{
		TPMKey:      addkey.PrivateKey,
		Certificate: addkey.Certificate,
	}

	// delete the key if it already exists in the list
	// it may have been loaded with no certificate or an old certificate
	a.keys = slices.DeleteFunc(a.keys, func(kk *key.SSHTPMKey) bool {
		return kk.Fingerprint() == k.Fingerprint()
	})

	a.keys = append(a.keys, k)

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
		s, err := ssh.NewSignerFromSigner(
			signer.NewSSHKeySigner(k, a.op, a.tpm,
				func(_ *keyfile.TPMKey) ([]byte, error) {
					// Shimming the function to get the correct type
					return a.pin(k)
				}))
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
			Comment: k.Description,
		})

		if k.Certificate != nil {
			agentKeys = append(agentKeys, &agent.Key{
				Format:  k.Certificate.Type(),
				Blob:    k.Certificate.Marshal(),
				Comment: k.Description,
			})
		}
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

	// Check that the key is not wrapped
	var wantKey []byte
	if cert, ok := key.(*ssh.Certificate); ok {
		wantKey = cert.Key.Marshal()
		alg = cert.Key.Type()
	} else {
		wantKey = key.Marshal()
	}

	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), wantKey) {
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
			if !bytes.Equal(s.PublicKey().Marshal(), wantKey) {
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

func (a *Agent) AddKey(k *key.SSHTPMKey) error {
	slog.Debug("called addkey")
	a.keys = append(a.keys, k)
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

func (a *Agent) Add(key agent.AddedKey) error {
	// This just proxies the Add call to all proxied agents
	// First to accept gets the key!
	slog.Debug("called add")
	for _, agent := range a.agents {
		if err := agent.Add(key); err == nil {
			return nil
		}
	}
	return nil
}

func (a *Agent) Remove(sshkey ssh.PublicKey) error {
	slog.Debug("called remove")
	a.mu.Lock()
	defer a.mu.Unlock()

	fp := ssh.FingerprintSHA256(sshkey)

	a.keys = slices.DeleteFunc(a.keys, func(k *key.SSHTPMKey) bool {
		if k.Fingerprint() == ssh.FingerprintSHA256(sshkey) {
			slog.Debug("deleting key from ssh-tpm-agent", slog.String("fingerprint", fp))
			return true
		}
		return false
	})

	for _, agent := range a.agents {
		lkeys, err := agent.List()
		if err != nil {
			slog.Debug("agent returned err on List()", slog.Any("err", err))
			continue
		}

		for _, k := range lkeys {
			if !bytes.Equal(k.Marshal(), sshkey.Marshal()) {
				continue
			}
			if err := agent.Remove(sshkey); err != nil {
				slog.Debug("agent returned err on Remove()", slog.Any("err", err))
			}
			slog.Debug("deleting key from an proxy agent", slog.String("fingerprint", fp))
			return nil
		}
	}
	slog.Debug("could not find key in any proxied agent", slog.String("fingerprint", fp))
	return fmt.Errorf("key not found")
}

func (a *Agent) RemoveAll() error {
	slog.Debug("called removeall")
	a.mu.Lock()
	defer a.mu.Unlock()

	a.keys = []*key.SSHTPMKey{}

	for _, agent := range a.agents {
		if err := agent.RemoveAll(); err == nil {
			return nil
		}
	}
	return nil
}

func (a *Agent) Lock(passphrase []byte) error {
	slog.Debug("called lock")
	return ErrOperationUnsupported
}

func (a *Agent) Unlock(passphrase []byte) error {
	slog.Debug("called unlock")
	return ErrOperationUnsupported
}

func LoadKeys(keyDir string) ([]*key.SSHTPMKey, error) {
	keyDir, err := filepath.EvalSymlinks(keyDir)
	if err != nil {
		return nil, err
	}

	var keys []*key.SSHTPMKey

	walkFunc := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".tpm") {
			slog.Debug("skipping key: does not have .tpm suffix", slog.String("name", path))
			return nil
		}

		f, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed reading %s", path)
		}

		k, err := key.Decode(f)
		if err != nil {
			if errors.Is(err, key.ErrOldKey) {
				slog.Info("TPM key is in an old format. Will not load it.", slog.String("key_path", path), slog.String("error", err.Error()))

			} else {
				slog.Debug("not a TPM sealed key", slog.String("key_path", path), slog.String("error", err.Error()))
			}
			return nil
		}

		keys = append(keys, k)

		slog.Debug("added TPM key", slog.String("name", path))
		return nil
	}

	err = filepath.WalkDir(keyDir, walkFunc)
	return keys, err
}

func NewAgent(listener *net.UnixListener, agents []agent.ExtendedAgent, tpmFetch func() transport.TPMCloser, ownerPassword func() ([]byte, error), pin func(*key.SSHTPMKey) ([]byte, error)) *Agent {
	a := &Agent{
		agents:   agents,
		tpm:      tpmFetch,
		op:       ownerPassword,
		listener: listener,
		pin:      pin,
		quit:     make(chan interface{}),
		keys:     []*key.SSHTPMKey{},
	}

	a.wg.Add(1)
	go a.serve()
	return a
}
