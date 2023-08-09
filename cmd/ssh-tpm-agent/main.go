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
	"github.com/foxboron/ssh-tpm-agent/contrib"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/pinentry"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2/transport"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
)

var Version string

const usage = `Usage:
    ssh-tpm-agent -l [PATH]

Options:
    -l PATH           Path of the UNIX socket to open, defaults to
                      $XDG_RUNTIME_DIR/ssh-tpm-agent.sock.

    -A PATH           Fallback ssh-agent sockets for additional key lookup.

    --print-socket    Prints the socket to STDIN.

    --key-dir PATH    Path of the directory to look for TPM sealed keys in,
                      defaults to $HOME/.ssh

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

func InstallUserUnits() error {
	d := utils.GetSystemdUserDir()
	if utils.DirExists(d) {
		files := contrib.GetServices()
		for name := range files {
			ff := path.Join(d, name)
			if utils.FileExists(ff) {
				log.Printf("%s exists. Not installing user units.\n", ff)
				return nil
			}
		}
		for name, data := range files {
			ff := path.Join(d, name)
			if err := os.WriteFile(ff, data, 0644); err != nil {
				return err
			}
		}
		return nil
	}
	log.Printf("Couldn't find %s, probably not running systemd?\n", d)
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		socketPath       string
		keyDir           string
		swtpmFlag        bool
		printSocketFlag  bool
		installUserUnits bool
	)

	defaultSocketPath := func() string {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			dir = "/var/tmp"
		}
		return path.Join(dir, "ssh-tpm-agent.sock")
	}()

	var sockets SocketSet

	flag.StringVar(&socketPath, "l", defaultSocketPath, "path of the UNIX socket to listen on")
	flag.Var(&sockets, "A", "fallback ssh-agent sockets")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&printSocketFlag, "print-socket", false, "print path of UNIX socket to stdout")
	flag.StringVar(&keyDir, "key-dir", utils.GetSSHDir(), "path of the directory to look for keys in")
	flag.BoolVar(&installUserUnits, "install-user-units", false, "install systemd user units")
	flag.Parse()

	if installUserUnits {
		InstallUserUnits()
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

	fi, err := os.Lstat(keyDir)
	if err != nil {
		log.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		log.Printf("Warning: %s is a symbolic link; will not follow it", keyDir)
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: ssh-tpm-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using a systemd service.")
	}

	var agents []sshagent.ExtendedAgent

	for _, s := range sockets.Value {
		conn, err := net.Dial("unix", s)
		if err != nil {
			log.Fatal(err)
		}
		agents = append(agents, sshagent.NewClient(conn))
	}

	var listener *net.UnixListener

	if os.Getenv("LISTEN_FDS") != "" {
		if err != nil {
			log.Fatal(err)
		}

		file := os.NewFile(uintptr(3), "ssh-tpm-agent.socket")
		fl, err := net.FileListener(file)
		if err != nil {
			log.Fatal(err)
		}
		var ok bool
		listener, ok = fl.(*net.UnixListener)
		if !ok {
			log.Fatalf("Socket-activation FD isn't a unix socket")
		}

		log.Println("Socket activated agent.")
	} else {
		if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
			log.Fatalln("Failed to create UNIX socket folder:", err)
		}
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socketPath})
		if err != nil {
			log.Fatalln("Failed to listen on UNIX socket:", err)
		}
		log.Printf("Listening on %v\n", socketPath)
	}

	a := agent.NewAgent(listener,
		agents,
		// TPM Callback
		func() (tpm transport.TPMCloser) {
			// the agent will close the TPM after this is called
			tpm, err := utils.GetTPM(swtpmFlag)
			if err != nil {
				log.Fatal(err)
			}
			return tpm
		},

		// PIN Callback
		func(key *key.Key) ([]byte, error) {
			keyHash := sha256.Sum256(key.Public.Bytes())
			keyInfo := fmt.Sprintf("ssh-tpm-agent/%x", keyHash)
			return pinentry.GetPinentry(keyInfo)
		},
	)

	// Signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Stop()
		}
	}()

	//TODO: Maybe we should allow people to not auto-load keys
	a.LoadKeys(keyDir)

	a.Wait()
}
