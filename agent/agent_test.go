package agent_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"math"
	"net"
	"path"
	"testing"
	"time"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
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
		// Keyring callback
		func() *keyring.ThreadKeyring { return &keyring.ThreadKeyring{} },
		// TPM Callback
		func() transport.TPMCloser { return tpm },
		// Owner password
		func() ([]byte, error) { return []byte(""), nil },
		// PIN Callback
		func(_ key.SSHTPMKeys) ([]byte, *keyring.Key, error) { return []byte(""), nil, nil },
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
				sshkey = *k.PublicKey
			}

			_, err = ag.Sign(sshkey, []byte("test"))
			if !errors.Is(err, c.wanterr) {
				t.Fatalf("failed signing: %v", err)
			}
		})
	}
}

func TestRemoveCertFromProxy(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	caEcdsa, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed creating CA key")
	}

	for _, c := range []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		wanterr error
		numkeys int
	}{
		{
			text:    "sign key",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			f:       keytest.MkKey,
			numkeys: 0,
		},
		{
			text:    "sign key cert",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			f:       keytest.MkCertificate(t, caEcdsa),
			numkeys: 1,
		},
	} {

		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			proxyagent := keytest.NewTestAgent(t, tpm)
			defer proxyagent.Stop()

			testagent := keytest.NewTestAgent(t, tpm)
			defer testagent.Stop()

			if err := testagent.AddKey(k); err != nil {
				t.Fatalf("failed saving key: %v", err)
			}

			if k.Certificate != nil {
				// If we have a certificate, include
				// the key without the certificate
				c := *k
				c.Certificate = nil
				if err := testagent.AddKey(&c); err != nil {
					t.Fatalf("failed saving key: %v", err)
				}
			}

			// Add testagent to proxyagent
			// We'll try to remove the key from testagent.
			proxyagent.AddProxyAgent(testagent)

			// Shim the certificate if there is one
			var sshkey ssh.PublicKey
			if k.Certificate != nil {
				sshkey = k.Certificate
			} else {
				sshkey = *k.PublicKey
			}

			if err := proxyagent.Remove(sshkey); err != nil {
				t.Fatalf("failed to remove key: %v", err)
			}

			// Check the key doesn't exist in the proxy nor the agent
			proxysl, err := proxyagent.List()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(proxysl) != c.numkeys {
				t.Fatalf("still keys in the agent. Should be 0")
			}

			sl, err := testagent.List()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(sl) != c.numkeys {
				t.Fatalf("still keys in the agent. Should be 0")
			}
		})
	}
}

func TestLifetime(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	t.Run("a key added with a lifetime is deleted when it runs out", func(t *testing.T) {
		socket := path.Join(t.TempDir(), "socket")
		unixList, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})
		if err != nil {
			t.Fatal(err)
		}
		defer unixList.Close()
		ag := agent.NewAgent(unixList,
			[]sshagent.ExtendedAgent{},
			func() *keyring.ThreadKeyring { return &keyring.ThreadKeyring{} },
			func() transport.TPMCloser { return tpm },
			func() ([]byte, error) { return []byte(""), nil },
			func(_ key.SSHTPMKeys) ([]byte, *keyring.Key, error) { return []byte(""), nil, nil },
		)
		defer ag.Stop()
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := sshagent.NewClient(conn)

		k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, []byte(""))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&sshagent.AddedKey{
			PrivateKey:   k,
			LifetimeSecs: 1,
		})); err != nil {
			t.Fatal(err)
		}
		if l, err := client.List(); err != nil || len(l) != 1 {
			t.Fatalf("want the key, got %d keys: %v", len(l), err)
		}
		time.Sleep(1100 * time.Millisecond)
		if l, err := client.List(); err != nil || len(l) != 0 {
			t.Fatalf("want no keys past the lifetime, got %d: %v", len(l), err)
		}
	})

	k, err := keytest.MkKey(t, tpm, tpm2.TPMAlgECC, 256, []byte(""), "")
	if err != nil {
		t.Fatal(err)
	}
	ca := keytest.MkECDSA(t, elliptic.P256())
	certified, err := keytest.MkCertificate(t, &ca)(t, tpm, tpm2.TPMAlgECC, 256, []byte(""), "")
	if err != nil {
		t.Fatal(err)
	}
	// with returns a copy of k that the agent deletes at expiry.
	with := func(k *key.SSHTPMKey, expiry time.Time) *key.SSHTPMKey {
		c := *k
		c.Expiry = expiry
		return &c
	}

	t.Run("only the keys past their lifetime go", func(t *testing.T) {
		ag := keytest.NewTestAgent(t, tpm)
		defer ag.Stop()

		gone := with(certified, time.Now().Add(-time.Second))
		stays := with(k, time.Now().Add(time.Hour))
		for _, k := range []*key.SSHTPMKey{gone, stays, certified} {
			if err := ag.AddKey(k); err != nil {
				t.Fatal(err)
			}
		}
		l, err := ag.List()
		if err != nil {
			t.Fatal(err)
		}
		// certified without a lifetime stays too
		if len(l) != 2 || !bytes.Equal(l[0].Blob, (*k.PublicKey).Marshal()) ||
			!bytes.Equal(l[1].Blob, certified.Certificate.Marshal()) {
			t.Fatalf("want the key with time left and the one without a lifetime, got %d keys", len(l))
		}
	})

	t.Run("a key past its lifetime neither signs nor is removed", func(t *testing.T) {
		ag := keytest.NewTestAgent(t, tpm)
		defer ag.Stop()

		gone := with(certified, time.Now().Add(-time.Second))
		if err := ag.AddKey(gone); err != nil {
			t.Fatal(err)
		}
		if _, err := ag.Sign(gone.Certificate, []byte("test")); !errors.Is(err, agent.ErrNoMatchPrivateKeys) {
			t.Fatalf("want ErrNoMatchPrivateKeys, got %v", err)
		}
		if err := ag.Remove(gone.Certificate); err == nil {
			t.Fatal("removed a key past its lifetime")
		}
	})
}

func TestCertLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) uint64 { return uint64(now.Add(d).Unix()) }
	for _, c := range []struct {
		text        string
		validBefore uint64
		secs        uint32
		expired     bool
	}{
		{"never expires", ssh.CertTimeInfinity, 0, false},
		{"valid for an hour", at(time.Hour), 3600 + 300, false},
		{"expired a minute ago, within the grace", at(-time.Minute), 240, false},
		{"expires with the grace now", at(-5 * time.Minute), 1, false},
		{"past the grace", at(-5*time.Minute - time.Second), 0, true},
		{"far future", at(100 * 365 * 24 * time.Hour), math.MaxInt32, false},
	} {
		t.Run(c.text, func(t *testing.T) {
			secs, expired := agent.CertLifetime(&ssh.Certificate{ValidBefore: c.validBefore}, now)
			if secs != c.secs || expired != c.expired {
				t.Fatalf("got %d %v, want %d %v", secs, expired, c.secs, c.expired)
			}
		})
	}
}
