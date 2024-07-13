package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/agent"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var Version string

const usage = `Usage:
    ssh-tpm-add [FILE]

Add a sealed TPM key to ssh-tpm-agent.

Example:
    $ ssh-tpm-add id_rsa.tpm`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	if len(os.Args) == 1 {
		fmt.Println(usage)
		return
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		fmt.Println("Can't find any ssh-tpm-agent socket.")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	path := os.Args[1]

	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	k, err := keyfile.Decode(b)
	if err != nil {
		log.Fatal(err)
	}

	client := sshagent.NewClient(conn)

	addedkey := sshagent.AddedKey{
		PrivateKey: k,
		Comment:    k.Description,
	}

	certStr := fmt.Sprintf("%s-cert.pub", strings.TrimSuffix(path, filepath.Ext(path)))
	if _, err := os.Stat(certStr); !errors.Is(err, os.ErrNotExist) {
		b, err := os.ReadFile(certStr)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			log.Fatal("failed parsing ssh certificate")
		}

		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			log.Fatal("failed parsing ssh certificate")
		}
		addedkey.Certificate = cert
		fmt.Printf("Identity added: %s\n", certStr)
	}

	_, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&addedkey))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Identity added: %s\n", path)
}
