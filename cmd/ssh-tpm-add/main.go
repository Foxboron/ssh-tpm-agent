package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/foxboron/ssh-tpm-agent/agent"
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

	client := sshagent.NewClient(conn)

	_, err = client.Extension(agent.SSH_TPM_AGENT_ADD, b)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Identity added: %s\n", path)
}
