package agent

import (
	"testing"
	"time"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Verify that ConfirmBeforeUse survives the Marshal/Parse round-trip used
// between ssh-tpm-add -c and the agent's tpm-add-key extension. This is the
// regression guard for the -c flag: if someone refactors ParseTPMKeyMsg and
// drops the setConstraints call, this fails.
func TestTPMKeyMsgConfirmRoundTrip(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		confirm bool
	}{
		{"no constraint", false},
		{"confirm constraint", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := MarshalTPMKeyMsg(&sshagent.AddedKey{
				PrivateKey:       k,
				Comment:          "test",
				ConfirmBeforeUse: tc.confirm,
			})

			parsed, err := ParseTPMKeyMsg(msg)
			if err != nil {
				t.Fatalf("ParseTPMKeyMsg: %v", err)
			}
			if parsed.GetConfirmBeforeUse() != tc.confirm {
				t.Fatalf("ConfirmBeforeUse: got %v want %v",
					parsed.GetConfirmBeforeUse(), tc.confirm)
			}
		})
	}
}

// The lifetime constraint survives the Marshal/Parse round-trip as the
// expiry of the key, and without one the key never expires.
func TestTPMKeyMsgLifetimeRoundTrip(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	parsed, err := ParseTPMKeyMsg(MarshalTPMKeyMsg(&sshagent.AddedKey{PrivateKey: k, LifetimeSecs: 60}))
	if err != nil {
		t.Fatal(err)
	}
	if exp := parsed.GetExpiry(); exp.Before(before.Add(60*time.Second)) || exp.After(time.Now().Add(60*time.Second)) {
		t.Fatalf("expiry %v, want 60s from %v", exp, before)
	}

	parsed, err = ParseTPMKeyMsg(MarshalTPMKeyMsg(&sshagent.AddedKey{PrivateKey: k}))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.GetExpiry().IsZero() {
		t.Fatalf("expiry %v without a lifetime", parsed.GetExpiry())
	}
}
