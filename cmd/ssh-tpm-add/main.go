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

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var Version string

const usage = `Usage:
    ssh-tpm-add [FILE ...]
    ssh-tpm-add --ca [URL] --user [USER] --host [HOSTNAME]

Options for CA provisioning:
    --ca URL               URL to the CA authority for CA key provisioning.
    --user USER            Username of the ssh server user.
    --host HOSTNAME        Hostname of the ssh server.

Add a sealed TPM key to ssh-tpm-agent. Allows CA key provisioning with the --ca
option.

Example:
    $ ssh-tpm-add id_rsa.tpm`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		caURL, host, user string
	)

	flag.StringVar(&caURL, "ca", "", "ca authority")
	flag.StringVar(&host, "host", "", "ssh hot")
	flag.StringVar(&user, "user", "", "remote ssh user")
	flag.Parse()

	socket := utils.EnvSocketPath("")
	if socket == "" {
		fmt.Println("Can't find any ssh-tpm-agent socket.")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if caURL != "" && host != "" {
		c := client.NewClient(caURL)
		rwc, err := transport.OpenTPM()
		if err != nil {
			log.Fatal(err)
		}
		k, cert, err := c.GetKey(rwc, user, host)
		if err != nil {
			log.Fatal(err)
		}

		sshagentclient := sshagent.NewClient(conn)
		addedkey := sshagent.AddedKey{
			PrivateKey:  k,
			Comment:     k.Description,
			Certificate: cert,
		}

		_, err = sshagentclient.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&addedkey))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity added from CA authority: %s\n", caURL)
		os.Exit(0)
	}

	var ignorefile bool
	var paths []string
	if len(os.Args) == 1 {
		sshdir := utils.SSHDir()
		paths = []string{
			fmt.Sprintf("%s/id_ecdsa.tpm", sshdir),
			fmt.Sprintf("%s/id_rsa.tpm", sshdir),
		}
		ignorefile = true
	} else if len(os.Args) != 1 {
		paths = os.Args[1:]
	}

	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			if ignorefile {
				continue
			}
			log.Fatal(err)
		}

		k, err := key.Decode(b)
		if err != nil {
			log.Fatal(err)
		}

		client := sshagent.NewClient(conn)

		if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(
			&sshagent.AddedKey{
				PrivateKey: k,
				Comment:    k.Description,
			},
		)); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity added: %s (%s)\n", path, k.Description)

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
			if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(
				&sshagent.AddedKey{
					PrivateKey:  k,
					Certificate: cert,
					Comment:     k.Description,
				},
			)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Identity added: %s (%s)\n", certStr, k.Description)
		}

	}
}
