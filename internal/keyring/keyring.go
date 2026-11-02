package keyring

import (
	"fmt"
	"log/slog"
	"time"

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
	return k.AddKeyWithTimeout(name, b, 0)
}

func (k *Keyring) AddKeyWithTimeout(name string, b []byte, timeout time.Duration) error {
	slog.Debug("addkey", slog.String("name", name))
	id, err := unix.AddKey("user", name, b, k.ringid)
	if err != nil {
		return fmt.Errorf("failed add-key: %v", err)
	}
	if timeout > 0 {
		if err := setKeyTimeout(id, timeout); err != nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
			return err
		}
	}
	return nil
}

func (k *Keyring) ReadKey(name string) (*Key, error) {
	return k.ReadKeyWithTimeout(name, 0)
}

func (k *Keyring) ReadKeyWithTimeout(name string, timeout time.Duration) (*Key, error) {
	slog.Debug("readkey", slog.String("name", name))
	id, err := unix.KeyctlSearch(k.ringid, "user", name, 0)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		if err := setKeyTimeout(id, timeout); err != nil {
			return nil, err
		}
	}
	b, err := ReadKeyIntoMemory(id)
	if err != nil {
		return nil, err
	}
	return b, err
}

func (k *Keyring) RemoveKey(name string) error {
	slog.Debug("removekey", slog.String("name", name))
	id, err := unix.KeyctlSearch(k.ringid, "user", name, 0)
	if err != nil {
		return fmt.Errorf("failed remove-key: %v", err)
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
	return err
}

func setKeyTimeout(id int, timeout time.Duration) error {
	seconds := int((timeout + time.Second - 1) / time.Second)
	if seconds < 1 {
		return fmt.Errorf("key timeout must be at least 1 second")
	}
	_, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, seconds, 0, 0)
	if err != nil {
		return fmt.Errorf("failed set-key-timeout: %v", err)
	}
	return nil
}
