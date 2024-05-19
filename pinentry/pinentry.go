package pinentry

import (
	"errors"

	"github.com/twpayne/go-pinentry"
)

var (
	ErrPinentryCancelled = errors.New("cancelled pinentry")
)

func GetPinentry(keyInfo string, description string, prompt string, title string) ([]byte, error) {
	// TODO: Include some additional key metadata
	client, err := pinentry.NewClient(
		pinentry.WithCommand("OPTION allow-external-password-cache"),
		pinentry.WithCommandf("SETKEYINFO %v", keyInfo),
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithDesc(description),
		pinentry.WithGPGTTY(),
		pinentry.WithPrompt(prompt),
		pinentry.WithTitle(title),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	switch pin, fromCache, err := client.GetPIN(); {
	case pinentry.IsCancelled(err):
		return nil, ErrPinentryCancelled
	case err != nil:
		return nil, err
	case fromCache:
		return []byte(pin), nil
	default:
		return []byte(pin), nil
	}
}

func GetPin(keyInfo string) ([]byte, error) {
	return GetPinentry(
		keyInfo,
		"Enter PIN for TPM key",
		"PIN:",
		"ssh-tpm-agent PIN entry",
	)
}

func GetOwnerPassword() ([]byte, error) {
	return GetPinentry(
		"ssh-tpm-agent/owner-password",
		"Enter owner password for TPM",
		"Owner password:",
		"ssh-tpm-agent owner password entry",
	)
}
