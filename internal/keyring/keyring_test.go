package keyring

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
)

func TestSaveAndGetData(t *testing.T) {
	keyring, err := SessionKeyring.CreateKeyring()
	if err != nil {
		t.Fatalf("failed getting keyring: %v", err)
	}

	b := []byte("test string")
	if err := keyring.AddKey("test", b); err != nil {
		t.Fatalf("err: %v", err)
	}

	bb, err := keyring.ReadKey("test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(b, bb.Read()) {
		t.Fatalf("strings not equal")
	}
}

func TestNoKey(t *testing.T) {
	keyring, err := SessionKeyring.CreateKeyring()
	if err != nil {
		t.Fatalf("failed getting keyring: %v", err)
	}
	_, err = keyring.ReadKey("this.key.does.not.exist")
	if !errors.Is(err, syscall.ENOKEY) {
		t.Fatalf("err: %v", err)
	}
}

func TestRemoveKey(t *testing.T) {
	keyring, err := SessionKeyring.CreateKeyring()
	if err != nil {
		t.Fatalf("failed getting keyring: %v", err)
	}
	b := []byte("test string")
	if err := keyring.AddKey("test-2", b); err != nil {
		t.Fatalf("err: %v", err)
	}

	bb, err := keyring.ReadKey("test-2")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(b, bb.Read()) {
		t.Fatalf("strings not equal")
	}

	if err = keyring.RemoveKey("test-2"); err != nil {
		t.Fatalf("failed removing key: %v", err)
	}
	_, err = keyring.ReadKey("test-2")
	if !errors.Is(err, syscall.ENOKEY) {
		t.Fatalf("we can still read the key")
	}
}
