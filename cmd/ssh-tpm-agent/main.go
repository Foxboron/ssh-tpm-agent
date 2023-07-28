package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/pinentry"
	swtpm "github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var (
	swtpmPath = "/var/tmp/ssh-tpm-agent"
)

// Smaller wrapper for getting the correct TPM instance
func getTPM(f bool) (transport.TPMCloser, error) {
	var tpm transport.TPMCloser
	var err error
	if f || os.Getenv("SSH_TPM_AGENT_SWTPM") != "" {
		if _, err := os.Stat(swtpmPath); errors.Is(err, os.ErrNotExist) {
			os.MkdirTemp(path.Dir(swtpmPath), path.Base(swtpmPath))
		}
		tpm, err = swtpm.OpenSwtpm(swtpmPath)
	} else {
		tpm, err = transport.OpenTPM()
	}
	if err != nil {
		return nil, err
	}
	return tpm, nil
}

func main() {
	flag.Usage = func() {
		fmt.Println("Usage here")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	setupFlag := flag.Bool("setup", false, "setup: configure a new TPM key")
	swtpmFlag := flag.Bool("swtpm", false, "use swtpm instead of actual tpm")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *setupFlag {
		tpm, err := getTPM(*swtpmFlag)
		if err != nil {
			log.Fatal(err)
		}
		defer tpm.Close()

		log.SetFlags(0)
		k, err := key.CreateKey(tpm, []byte("123"))
		if err != nil {
			log.Fatal(err)
		}
		sshKey, err := k.SSHPublicKey()
		if err != nil {
			log.Fatal(err)
		}
		if err := agent.SaveKey(k); err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}

		tpmFetch := func() (tpm transport.TPMCloser) {
			// the agent will close the TPM after this is called
			tpm, err := getTPM(*swtpmFlag)
			if err != nil {
				log.Fatal(err)
			}
			return tpm
		}
		pin := func(_ *key.Key) ([]byte, error) {
			return pinentry.GetPinentry()
		}
		agent.RunAgent(*socketPath, tpmFetch, pin)
	}
}
