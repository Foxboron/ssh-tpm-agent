package agent

import (
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Verify that both add-key flags survive the tpm-add-key extension's
// Marshal/Parse round-trip.
func TestTPMKeyMsgFlagsRoundTrip(t *testing.T) {
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
		name         string
		confirm      bool
		lifetimeSecs uint32
		lifetimeSet  bool
		cacheSecs    uint32
		cacheSet     bool
	}{
		{"no flags", false, 0, false, 0, false},
		{"confirm flag", true, 0, false, 0, false},
		{"lifetime flag", false, 300, true, 0, false},
		{"zero lifetime flag", false, 0, true, 0, false},
		{"cache timeout flag", false, 0, false, 300, true},
		{"all flags", true, 300, true, 300, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := MarshalTPMKeyMsgWithOptions(&sshagent.AddedKey{
				PrivateKey:       k,
				Comment:          "test",
				ConfirmBeforeUse: tc.confirm,
				LifetimeSecs:     tc.lifetimeSecs,
			}, tc.lifetimeSet, tc.cacheSecs, tc.cacheSet)

			parsed, err := ParseTPMKeyMsg(msg)
			if err != nil {
				t.Fatalf("ParseTPMKeyMsg: %v", err)
			}
			if parsed.GetConfirmBeforeUse() != tc.confirm {
				t.Fatalf("ConfirmBeforeUse: got %v want %v",
					parsed.GetConfirmBeforeUse(), tc.confirm)
			}
			if parsed.LifetimeSecs != tc.lifetimeSecs {
				t.Fatalf("LifetimeSecs: got %d want %d", parsed.LifetimeSecs, tc.lifetimeSecs)
			}
			if parsed.LifetimeSet != tc.lifetimeSet {
				t.Fatalf("LifetimeSet: got %v want %v", parsed.LifetimeSet, tc.lifetimeSet)
			}
			if parsed.CacheTimeoutSecs != tc.cacheSecs {
				t.Fatalf("CacheTimeoutSecs: got %d want %d", parsed.CacheTimeoutSecs, tc.cacheSecs)
			}
			if parsed.CacheTimeoutSet != tc.cacheSet {
				t.Fatalf("CacheTimeoutSet: got %v want %v", parsed.CacheTimeoutSet, tc.cacheSet)
			}
		})
	}
}
