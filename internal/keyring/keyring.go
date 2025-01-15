package keyring

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

var (
	SessionKeyring *Keyring = &Keyring{ringid: unix.KEY_SPEC_SESSION_KEYRING}
)

type Keyring struct {
	ringid int
}

func (ring *Keyring) CreateKeyring() (*Keyring, error) {
	id, err := unix.KeyctlJoinSessionKeyring("ssh-tpm-agent")
	if err != nil {
		return nil, err
	}

	return &Keyring{ringid: id}, nil
}

func (k *Keyring) AddKey(name string, b []byte) error {
	slog.Debug("addkey", slog.String("name", name))
	_, err := unix.AddKey("user", name, b, k.ringid)
	if err != nil {
		return fmt.Errorf("failed add-key: %v", err)
	}
	return nil
}

func (k *Keyring) ReadKey(name string) (*Key, error) {
	slog.Debug("readkey", slog.String("name", name))
	id, err := unix.RequestKey("user", name, "", k.ringid)
	if err != nil {
		return nil, err
	}
	b, err := ReadKeyIntoMemory(id)
	if err != nil {
		return nil, err
	}
	return b, err
}

func (k *Keyring) RemoveKey(name string) error {
	slog.Debug("removekey", slog.String("name", name))
	id, err := unix.RequestKey("user", name, "", k.ringid)
	if err != nil {
		return fmt.Errorf("failed remove-key: %v", err)
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
	return err
}
