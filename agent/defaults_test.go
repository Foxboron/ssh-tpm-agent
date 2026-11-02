package agent

import (
	"testing"

	"github.com/foxboron/ssh-tpm-agent/key"
)

func TestApplyDefaults(t *testing.T) {
	a := &Agent{
		defaultLifetimeSecs:     30,
		defaultLifetimeSet:      true,
		defaultCacheTimeoutSecs: 60,
		defaultCacheTimeoutSet:  true,
	}

	keyWithDefaults := &key.SSHTPMKey{}
	a.applyDefaults(keyWithDefaults)
	if keyWithDefaults.LifetimeSecs != 30 || !keyWithDefaults.LifetimeSet {
		t.Fatalf("lifetime defaults not applied: %+v", keyWithDefaults)
	}
	if keyWithDefaults.CacheTimeoutSecs != 60 || !keyWithDefaults.CacheTimeoutSet {
		t.Fatalf("cache-timeout defaults not applied: %+v", keyWithDefaults)
	}

	keyWithOverrides := &key.SSHTPMKey{
		LifetimeSecs:     5,
		LifetimeSet:      true,
		CacheTimeoutSecs: 10,
		CacheTimeoutSet:  true,
	}
	a.applyDefaults(keyWithOverrides)
	if keyWithOverrides.LifetimeSecs != 5 || keyWithOverrides.CacheTimeoutSecs != 10 {
		t.Fatalf("explicit defaults were overwritten: %+v", keyWithOverrides)
	}
}
