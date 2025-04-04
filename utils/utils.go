package utils

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"

	"github.com/foxboron/ssh-tpm-agent/contrib"
	"github.com/google/go-tpm/tpm2"
)

func SSHDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}

	return path.Join(dirname, ".ssh")
}

func FileExists(s string) bool {
	_, err := os.Stat(s)

	return !errors.Is(err, fs.ErrNotExist)
}

// This is the sort of things I swore I'd never write.
// but here we are.
func fmtSystemdInstallPath() string {
	DESTDIR := ""
	if val, ok := os.LookupEnv("DESTDIR"); ok {
		DESTDIR = val
	}

	PREFIX := "/usr/"
	if val, ok := os.LookupEnv("PREFIX"); ok {
		PREFIX = val
	}

	return path.Join(DESTDIR, PREFIX, "lib/systemd")
}

// Installs user units to the target system.
// It will either place the files under $HOME/.config/systemd/user or if global
// is supplied (through --install-system) into system user directories.
//
// Passing the env TEMPLATE_BINARY will use /usr/bin/ssh-tpm-agent for the
// binary in the service
func InstallUserUnits(global bool) error {
	if global || os.Getuid() == 0 { // If ran as root, install global system units
		return installUnits(path.Join(fmtSystemdInstallPath(), "/user/"), contrib.EmbeddedUserServices())
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	return installUnits(path.Join(dirname, ".config/systemd/user"), contrib.EmbeddedUserServices())
}

func InstallHostkeyUnits() error {
	return installUnits(path.Join(fmtSystemdInstallPath(), "/system/"), contrib.EmbeddedSystemServices())
}

func installUnits(installPath string, files map[string][]byte) (err error) {
	execPath := os.Getenv("TEMPLATE_BINARY")
	if execPath == "" {
		execPath, err = os.Executable()
		if err != nil {
			return err
		}
	}

	if !FileExists(installPath) {
		if err := os.MkdirAll(installPath, 0o750); err != nil {
			return fmt.Errorf("creating service installation directory: %w", err)
		}
	}

	for name := range files {
		servicePath := path.Join(installPath, name)
		if FileExists(servicePath) {
			fmt.Printf("%s exists. Not installing units.\n", servicePath)
			return nil
		}
	}

	for name, data := range files {
		servicePath := path.Join(installPath, name)

		f, err := os.OpenFile(servicePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()

		t := template.Must(template.New("service").Parse(string(data)))
		if err = t.Execute(f, &map[string]string{
			"GoBinary": execPath,
		}); err != nil {
			return err
		}

		fmt.Printf("Installed %s\n", servicePath)
	}

	return nil
}

func InstallSshdConf() error {
	// If ran as root, install sshd config
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("needs to be run as root")
	}

	sshdConfInstallPath := "/etc/ssh/sshd_config.d/"

	if !FileExists(sshdConfInstallPath) {
		return nil
	}

	files := contrib.EmbeddedSshdConfig()
	for name := range files {
		ff := path.Join(sshdConfInstallPath, name)
		if FileExists(ff) {
			fmt.Printf("%s exists. Not installing sshd config.\n", ff)
			return nil
		}
	}
	for name, data := range files {
		ff := path.Join(sshdConfInstallPath, name)
		if err := os.WriteFile(ff, data, 0o644); err != nil {
			return fmt.Errorf("failed writing sshd conf: %v", err)
		}
		fmt.Printf("Installed %s\n", ff)
	}
	fmt.Println("Restart sshd: systemd restart sshd")
	return nil
}

func GetParentHandle(ph string) (tpm2.TPMHandle, error) {
	switch ph {
	case "endoresement", "e":
		return tpm2.TPMRHEndorsement, nil
	case "null", "n":
		return tpm2.TPMRHNull, nil
	case "plattform", "p":
		return tpm2.TPMRHPlatform, nil
	case "owner", "o":
		fallthrough
	default:
		return tpm2.TPMRHOwner, nil
	}
}
