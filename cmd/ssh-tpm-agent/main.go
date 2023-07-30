package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/pinentry"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2/transport"
)

var Version string

const usage = `Usage:
    ssh-tpm-agent -l [PATH]

Options:
    -l                path of the UNIX socket to listen on, defaults to
                      $XDG_RUNTIME_DIR/ssh-tpm-agent.sock

    --print-socket    prints the socket to STDIN

ssh-tpm-agent is a program that loads TPM sealed keys for public key
authentication. It is an ssh-agent(1) compatible program and can be used for
ssh(1) authentication.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in .tpm suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

Use ssh-tpm-keygen to create new keys.

The agent loads all TPM sealed keys from $HOME/.ssh.

Example:
    $ ssh-tpm-agent &
    $ export SSH_AUTH_SOCK=$(ssh-tpm-agent --print-socket)
    $ ssh git@github.com`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		socketPath string
		swtpmFlag  bool
		printSocketFlag bool
	)

	defaultSocketPath := func() (string) {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			dir = "/var/tmp"
		}
		return path.Join(dir, "ssh-tpm-agent.sock")
	}()

	flag.StringVar(&socketPath, "l", defaultSocketPath, "path of the UNIX socket to listen on")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&printSocketFlag, "print-socket", false, "print path of UNIX socket to stdout")
	flag.Parse()

	if socketPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	if printSocketFlag {
		fmt.Println(socketPath)
		os.Exit(0)
	}

	tpmFetch := func() (tpm transport.TPMCloser) {
		// the agent will close the TPM after this is called
		tpm, err := utils.GetTPM(swtpmFlag)
		if err != nil {
			log.Fatal(err)
		}
		return tpm
	}
	pin := func(key *key.Key) ([]byte, error) {
		keyHash := sha256.Sum256(key.Public.Bytes())
		keyInfo := fmt.Sprintf("ssh-tpm-agent/%x", keyHash)
		return pinentry.GetPinentry(keyInfo)
	}
	agent.RunAgent(socketPath, tpmFetch, pin)
}
