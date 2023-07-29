package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
    -l    path of the UNIX socket to listen on

ssh-tpm-agent is a program that loads TPM sealed keys for public key
authentication. It is an ssh-agent(1) compatible program and can be used for
ssh(1) authentication.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in .tpm suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

Use ssh-tpm-keygen to create new keys.

The agent loads all TPM sealed keys from $HOME/.ssh.

Example:
    $ ssh-tpm-agent -l /var/tmp/tmp/tpm.sock
    $ export SSH_AUTH_SOCK="/var/tmp/tpm.sock"
    $ ssh git@github.com`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		socketPath string
		swtpmFlag  bool
	)

	flag.StringVar(&socketPath, "l", "", "path of the UNIX socket to listen on")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if socketPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	tpmFetch := func() (tpm transport.TPMCloser) {
		// the agent will close the TPM after this is called
		tpm, err := utils.GetTPM(swtpmFlag)
		if err != nil {
			log.Fatal(err)
		}
		return tpm
	}
	pin := func(_ *key.Key) ([]byte, error) {
		return pinentry.GetPinentry()
	}
	agent.RunAgent(socketPath, tpmFetch, pin)
}
