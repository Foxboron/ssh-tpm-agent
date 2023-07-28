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

Generate new sealed keys for ssh-tpm-agent.`

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
