package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/internal/lsm"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/landlock-lsm/go-landlock/landlock"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var Version string

const usage = `Usage:
    ssh-tpm-agent [OPTIONS]
    ssh-tpm-agent -l [PATH]
    ssh-tpm-agent --install-user-units

Options:
    -l PATH                Path of the UNIX socket to open, defaults to
                           $XDG_RUNTIME_DIR/ssh-tpm-agent.sock.

    -A PATH                Fallback ssh-agent sockets for additional key lookup.

    --print-socket         Prints the socket to STDIN.

    --key-dir PATH         Path of the directory to look for TPM sealed keys in,
                           defaults to $HOME/.ssh

    --no-load              Do not load TPM sealed keys by default.

    -o, --owner-password   Ask for the owner password.

    --no-cache             The agent will not cache key passwords.


    --hierarchy HIERARCHY  Preload the agent with a hierarchy key.
                                owner, o (default)
                                endorsement, e
                                null, n
                                platform, p

    -d                     Enable debug logging.

    --install-user-units   Installs systemd user units for using ssh-tpm-agent
                           as a service.

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
		noCache                          bool
		hierarchy                        string
	)

	var sockets SocketSet

	flag.StringVar(&socketPath, "l", func(s string) string { return utils.EnvSocketPath(s) }(socketPath), "path of the UNIX socket to listen on")
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
	flag.BoolVar(&noCache, "no-cache", false, "do not cache key passwords")
	flag.StringVar(&hierarchy, "hierarchy", "", "hierarchy for the created key")
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
		lsm.RestrictAdditionalPaths(landlock.RWFiles(s))
		conn, err := net.Dial("unix", s)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		agents = append(agents, sshagent.NewClient(conn))
	}

	// Ensure we can rw socket path
	lsm.RestrictAdditionalPaths(landlock.RWFiles(socketPath))
	listener, err := createListener(socketPath)
	if err != nil {
		slog.Error("creating listener", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// TODO: Ensure the agent also uses thix context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentkeyring, err := keyring.NewThreadKeyring(ctx, keyring.SessionKeyring)
	if err != nil {
		log.Fatal(err)
	}

	// We need to pre-read all the keys before we run landlock
	var keys []key.SSHTPMKeys
	if !noLoad {
		keys, err = agent.LoadKeys(keyDir)
		if err != nil {
			log.Fatalf("can't preload keys from ~/.ssh: %v", err)
		}
	}

	// Try to landlock everything before we run the agent
	lsm.RestrictAgentFiles()
	if err := lsm.Restrict(); err != nil {
		log.Fatal(err)
	}

	agent := agent.NewAgent(listener, agents,

		// Keyring Callback
		func() *keyring.ThreadKeyring {
			return agentkeyring
		},

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
				return askpass.ReadPassphrase("Enter owner password for TPM", askpass.RP_USE_ASKPASS)
			} else {
				ownerPassword := os.Getenv("SSH_TPM_AGENT_OWNER_PASSWORD")
				return []byte(ownerPassword), nil
			}
		},

		// PIN Callback with caching
		// SSHKeySigner in signer/signer.go resets this value if
		// we get a TPMRCAuthFail
		func(key key.SSHTPMKeys) ([]byte, error) {
			auth, err := agentkeyring.ReadKey(key.Fingerprint())
			if err == nil {
				slog.Debug("providing cached userauth for key", slog.String("fp", key.Fingerprint()))
				// TODO: This is not great, but easier for now
				return auth.Read(), nil
			} else if errors.Is(err, syscall.ENOKEY) || errors.Is(err, syscall.EACCES) {
				keyInfo := fmt.Sprintf("Enter passphrase for (%s): ", key.GetDescription())
				// TODOt kjk: askpass should box the byte slice
				userauth, err := askpass.ReadPassphrase(keyInfo, askpass.RP_USE_ASKPASS)
				fmt.Println(err)
				if !noCache && err == nil {
					slog.Debug("caching userauth for key in keyring", slog.String("fp", key.Fingerprint()))
					if err := agentkeyring.AddKey(key.Fingerprint(), userauth); err != nil {
						return nil, err
					}
				}
				return userauth, err
			}
			return nil, fmt.Errorf("failed getting pin for key: %w", err)
		},
	)

	// Signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	signal.Notify(c, syscall.SIGINT)
	go func() {
		for range c {
			agent.Stop()
		}
	}()

	if !noLoad {
		agent.LoadKeys(keys)
	}

	if hierarchy != "" {
		if err := agent.AddHierarchyKeys(hierarchy); err != nil {
			log.Fatal(err)
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
