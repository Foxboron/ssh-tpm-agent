package utils

import (
	"errors"
	"io/fs"
	"os"
	"path"
)

func GetSSHDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}
	return path.Join(dirname, ".ssh")
}

func GetSystemdUserDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}
	return path.Join(dirname, ".config/systemd/user")
}

func DirExists(s string) bool {
	info, err := os.Stat(s)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return info.IsDir()
}

func FileExists(s string) bool {
	info, err := os.Stat(s)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return !info.IsDir()
}
