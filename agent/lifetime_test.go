package agent_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestTPMKeyLifetime(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Net: "unix", Name: filepath.Join(t.TempDir(), "agent.sock"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ring, err := keyring.NewThreadKeyring(ctx, keyring.SessionKeyring)
	if err != nil {
		t.Fatal(err)
	}
	ag := agent.NewAgent(listener, nil, func() *keyring.ThreadKeyring { return ring },
		func() transport.TPMCloser { return tpm },
		func() ([]byte, error) { return nil, nil },
		func(key.SSHTPMKeys) ([]byte, *keyring.Key, error) { return nil, nil, nil },
	)
	defer ag.Stop()

	k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, nil)
	if err != nil {
		t.Fatal(err)
	}
	addWithLifetime := func(lifetime uint32, lifetimeSet bool) {
		t.Helper()
		_, err := ag.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsgWithLifetime(&sshagent.AddedKey{
			PrivateKey: k, LifetimeSecs: lifetime,
		}, lifetimeSet))
		if err != nil {
			t.Fatal(err)
		}
	}
	add := func(lifetime uint32) {
		addWithLifetime(lifetime, lifetime != 0)
	}
	listCount := func() int {
		t.Helper()
		keys, err := ag.List()
		if err != nil {
			t.Fatal(err)
		}
		return len(keys)
	}

	// Re-adding a key without a lifetime cancels its old timer.
	add(1)
	add(0)
	time.Sleep(1100 * time.Millisecond)
	if got := listCount(); got != 1 {
		t.Fatalf("re-added key disappeared: got %d identities", got)
	}

	add(1)
	if got := listCount(); got != 1 {
		t.Fatalf("new key missing: got %d identities", got)
	}

	// Expiration removes the identity.
	if err := ring.AddKey(k.Fingerprint(), []byte("cached passphrase")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for listCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := listCount(); got != 0 {
		t.Fatalf("expired key remains listed: got %d identities", got)
	}

	// Expiration removes the cached passphrase.
	if _, err := ring.ReadKey(k.Fingerprint()); !errors.Is(err, syscall.ENOKEY) {
		t.Fatalf("cached passphrase remains after expiry: %v", err)
	}
	if _, err := ag.Sign(*k.PublicKey, []byte("test")); !errors.Is(err, agent.ErrNoMatchPrivateKeys) {
		t.Fatalf("expired key can still sign or returned unexpected error: %v", err)
	}

	// An explicitly set zero lifetime expires immediately.
	addWithLifetime(0, true)
	deadline = time.Now().Add(1 * time.Second)
	for listCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := listCount(); got != 0 {
		t.Fatalf("zero-lifetime key remains listed: got %d identities", got)
	}
}
