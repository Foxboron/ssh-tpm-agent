package key_test

import (
	"crypto"
	"io"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestHierKey(t *testing.T) {
	tpm, err := utils.GetFixedSim()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer tpm.Close()

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)

	if hkey.Fingerprint() != "SHA256:8kry+y93GpsJYho0GoIUpC6Ja7KFHajgqqXPTadlCPg" {
		t.Fatalf("ssh key fingerprint does not match")
	}
}

func TestHierKeySigning(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer tpm.Close()

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)

	h := crypto.SHA256.New()
	h.Write([]byte("message"))
	b := h.Sum(nil)

	_, err = hkey.Sign(tpm, []byte(nil), []byte(nil), b[:], tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestHierKeySigner(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer tpm.Close()

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)
	signer := hkey.Signer(&keyring.ThreadKeyring{},
		func() ([]byte, error) { return []byte(nil), nil },
		func() transport.TPMCloser { return tpm },
		func(_ *keyfile.TPMKey) ([]byte, error) { return []byte(nil), nil },
	)
	h := crypto.SHA256.New()
	h.Write([]byte("message"))
	b := h.Sum(nil)
	_, err = signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("message")
	}
}
