package keyring

import (
	"golang.org/x/sys/unix"
)

func ReadKeyIntoMemory(id int) ([]byte, error) {
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), nil, 0)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, sz)

	if _, err = unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), buffer, 0); err != nil {
		return nil, err
	}

	return buffer, nil
}
