package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"golang.org/x/term"
)

var Version string

const usage = `Usage:
    ssh-tpm-agent [OPTIONS]
    ssh-tpm-agent -l [PATH]
    ssh-tpm-agent --install-user-units

Options:
    -l PATH                 Path of the UNIX socket to open, defaults to
                            $XDG_RUNTIME_DIR/ssh-tpm-agent.sock.

    -A PATH                 Fallback ssh-agent sockets for additional key lookup.

    --print-socket          Prints the socket to STDIN.

    --key-dir PATH          Path of the directory to look for TPM sealed keys in,
                            defaults to $HOME/.ssh

    --no-load               Do not load TPM sealed keys by default.

    -o, --owner-password    Ask for the owner password.

    -d                      Enable debug logging.

    --install-user-units    Installs systemd system units and sshd configs for using
                            ssh-tpm-agent as a hostkey agent.

ssh-tpm-agent is a program that loads TPM sealed keys for public key
authentication. It is an ssh-agent(1) compatible program and can be used for
ssh(1) authentication.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in .tpm suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

Use ssh-tpm-keygen to create new keys.

The agent loads all TPM sealed keys from $HOME/.ssh, unless --key-dir is
specified.

Example:
    $ ssh-tpm-agent &
    $ export SSH_AUTH_SOCK=$(ssh-tpm-agent --print-socket)
    $ ssh git@github.com`

type SocketSet struct {
	Value []string
}

func (s SocketSet) String() string {
	return "set"
}

func (s *SocketSet) Set(p string) error {
	if !slices.Contains(s.Value, p) {
		s.Value = append(s.Value, p)
	}
	return nil
}

func (s SocketSet) Type() string {
	return "[PATH]"
}

func NewSocketSet(allowed []string, d string) *SocketSet {
	return &SocketSet{
		Value: []string{},
	}
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		socketPath, keyDir               string
		swtpmFlag, printSocketFlag       bool
		installUserUnits, system, noLoad bool
		askOwnerPassword, debugMode      bool
	)

	envSocketPath := func() string {
		if val, ok := os.LookupEnv("SSH_AUTH_SOCK"); ok && socketPath == "" {
			return val
		}

		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			dir = "/var/tmp"
		}
		return path.Join(dir, "ssh-tpm-agent.sock")
	}()

	var sockets SocketSet

	flag.StringVar(&socketPath, "l", envSocketPath, "path of the UNIX socket to listen on")
	flag.Var(&sockets, "A", "fallback ssh-agent sockets")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&printSocketFlag, "print-socket", false, "print path of UNIX socket to stdout")
	flag.StringVar(&keyDir, "key-dir", "", "path of the directory to look for keys in")
	flag.BoolVar(&installUserUnits, "install-user-units", false, "install systemd user units")
	flag.BoolVar(&system, "install-system", false, "install systemd user units")
	flag.BoolVar(&noLoad, "no-load", false, "don't load TPM sealed keys")
	flag.BoolVar(&askOwnerPassword, "o", false, "ask for the owner password")
	flag.BoolVar(&askOwnerPassword, "owner-password", false, "ask for the owner password")
	flag.BoolVar(&debugMode, "d", false, "debug mode")
	flag.Parse()

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if debugMode {
		opts.Level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))

	slog.SetDefault(logger)

	if installUserUnits {
		if err := utils.InstallUserUnits(system); err != nil {
			log.Fatal(err)
			fmt.Println(err.Error())
			os.Exit(1)
		}

		fmt.Println("Enable with: systemctl --user enable --now ssh-tpm-agent.socket")
		os.Exit(0)
	}

	if socketPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	if printSocketFlag {
		fmt.Println(socketPath)
		os.Exit(0)
	}

	if keyDir == "" {
		keyDir = utils.SSHDir()
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		slog.Info("Warning: ssh-tpm-agent is meant to run as a background daemon.")
		slog.Info("Running multiple instances is likely to lead to conflicts.")
		slog.Info("Consider using a systemd service.")
	}

	var agents []sshagent.ExtendedAgent

	for _, s := range sockets.Value {
		conn, err := net.Dial("unix", s)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		agents = append(agents, sshagent.NewClient(conn))
	}

	listener, err := createListener(socketPath)
	if err != nil {
		slog.Error("creating listener", slog.String("error", err.Error()))
		os.Exit(1)
	}

	agent := agent.NewAgent(listener, agents,

		// TPM Callback
		func() (tpm transport.TPMCloser) {
			// the agent will close the TPM after this is called
			tpm, err := utils.TPM(swtpmFlag)
			if err != nil {
				log.Fatal(err)
			}
			return tpm
		},

		// Owner password
		func() ([]byte, error) {
			if askOwnerPassword {
				return askpass.ReadPassphrase("Enter owner password for TPM", askpass.RP_USE_ASKPASS), nil
			} else {
				ownerPassword := os.Getenv("SSH_TPM_AGENT_OWNER_PASSWORD")

				return []byte(ownerPassword), nil
			}
		},

		// PIN Callback
		func(key *key.SSHTPMKey) ([]byte, error) {
			pbytes := tpm2.New2B(key.Pubkey)
			keyHash := sha256.Sum256(pbytes.Bytes())
			keyInfo := fmt.Sprintf("ssh-tpm-agent/%x", keyHash)
			return askpass.ReadPassphrase(keyInfo, askpass.RP_USE_ASKPASS), nil
		},
	)

	// Signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			agent.Stop()
		}
	}()

	if !noLoad {
		if err := agent.LoadKeys(keyDir); err != nil {
			slog.Error("loading keys", slog.String("error", err.Error()))
		}
	}

	agent.Wait()
}

func createListener(socketPath string) (*net.UnixListener, error) {
	if _, ok := os.LookupEnv("LISTEN_FDS"); ok {
		f := os.NewFile(uintptr(3), "ssh-tpm-agent.socket")

		fListener, err := net.FileListener(f)
		if err != nil {
			return nil, err
		}

		listener, ok := fListener.(*net.UnixListener)
		if !ok {
			return nil, fmt.Errorf("socket-activation file descriptor isn't an unix socket")
		}

		slog.Info("Activated agent by socket")
		return listener, nil
	}

	_ = os.Remove(socketPath)

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o770); err != nil {
		return nil, fmt.Errorf("creating UNIX socket directory: %w", err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socketPath})
	if err != nil {
		return nil, err
	}

	slog.Info("Listening on socket", slog.String("path", socketPath))
	return listener, nil
}
