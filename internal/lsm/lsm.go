package lsm

import (
	"log/slog"
	"os"

	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/landlock-lsm/go-landlock/landlock"
)

var rules []landlock.Rule

func HasLandlock() bool {
	_, ok := os.LookupEnv("SSH_TPM_LANDLOCK")
	return ok
}

func RestrictAdditionalPaths(r ...landlock.Rule) {
	rules = append(rules, r...)
}

func RestrictAgentFiles() {
	RestrictAdditionalPaths(
		// Probably what we need to do for most askpass binaries
		landlock.RWDirs(
			"/usr/lib",
		).IgnoreIfMissing(),
		// Default Go paths
		landlock.ROFiles(
			"/proc/sys/net/core/somaxconn",
			"/etc/localtime",
			"/dev/null",
		),
		// We almost always want to read the TPM
		landlock.RWFiles(
			"/dev/tpm0",
			"/dev/tpmrm0",
		),
		// Ensure we can read+exec askpass binaries
		landlock.ROFiles(
			askpass.SSH_ASKPASS_DEFAULTS...,
		).IgnoreIfMissing(),
	)
}

func Restrict() error {
	if !HasLandlock() {
		return nil
	}
	slog.Debug("sandboxing with landlock")
	for _, r := range rules {
		slog.Debug("landlock", slog.Any("rule", r))
	}
	landlock.V5.BestEffort().RestrictNet()
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
