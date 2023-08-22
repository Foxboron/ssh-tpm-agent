package utils

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/foxboron/ssh-tpm-agent/contrib"
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

// Installs user units to the target system.
// It will either place the files under $HOME/.config/systemd/user or if global
// is supplied (through --install-s directories. s
//
// Passing the env TEMPLATE_BINARY will use /usr/bin/ssh-tpm-agent for the
// binary in the service
func InstallUserUnits(global bool) error {
	var exPath string
	var serviceInstallPath string
	if global {
		serviceInstallPath = "/usr/lib/systemd/user/"
	} else {
		serviceInstallPath = GetSystemdUserDir()
	}
	// TODO: Use in a Makefile
	if s := os.Getenv("TEMPLATE_BINARY"); s != "" {
		exPath = "/usr/bin/ssh-tpm-agent"
	} else {
		ex, err := os.Executable()
		if err != nil {
			return err
		}
		exPath = filepath.Dir(ex)
	}
	if DirExists(serviceInstallPath) {
		files := contrib.GetUserServices()
		for name := range files {
			ff := path.Join(serviceInstallPath, name)
			if FileExists(ff) {
				fmt.Printf("%s exists. Not installing user units.\n", ff)
				return nil
			}
		}
		for name, data := range files {
			ff := path.Join(serviceInstallPath, name)
			serviceFile, err := os.OpenFile(ff, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			t := template.Must(template.New("service").Parse(string(data)))
			if err = t.Execute(serviceFile, &struct {
				GoBinary string
			}{
				GoBinary: exPath,
			}); err != nil {
				return err
			}

			fmt.Printf("Installed %s\n", ff)
		}
		fmt.Println("Enable with: systemctl --user enable --now ssh-tpm-agent.socket")
		return nil
	}
	fmt.Printf("Couldn't find %s, probably not running systemd?\n", serviceInstallPath)
	return nil
}
