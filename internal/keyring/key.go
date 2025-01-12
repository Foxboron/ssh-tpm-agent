package keyring

import (
	"github.com/awnumar/memcall"
	"golang.org/x/sys/unix"
)

// Key is a boxed byte slice where we allocate the underlying memory with memcall
type Key struct {
	b []byte
}

func (k *Key) Read() []byte {
	if k == nil {
		return []byte{}
	}
	return k.b
}

func (k *Key) Free() error {
	return memcall.Free(k.b)
}

func ReadKeyIntoMemory(id int) (*Key, error) {
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), nil, 0)
	if err != nil {
		return nil, err
	}

	buffer, err := memcall.Alloc(sz)
	if err != nil {
		return nil, err
	}

	if _, err = unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), buffer, 0); err != nil {
		return nil, err
	}

	if err := memcall.Lock(buffer); err != nil {
		return nil, err
	}

	return &Key{buffer}, nil
}
