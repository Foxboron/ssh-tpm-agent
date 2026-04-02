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
	"github.com/foxboron/ssh-tpm-agent/internal/lsm"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var Version string

const usage = `Usage:
    ssh-tpm-add [-c] [FILE ...]
    ssh-tpm-add --ca [URL] --user [USER] --host [HOSTNAME]

Options:
    -c                     Require confirmation via SSH_ASKPASS before each
                           use of the key for signing.

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

	var caURL, host, user string
	var confirm bool

	flag.StringVar(&caURL, "ca", "", "ca authority")
	flag.StringVar(&host, "host", "", "ssh hot")
	flag.StringVar(&user, "user", "", "remote ssh user")
	flag.BoolVar(&confirm, "c", false, "require confirmation before each use")
	flag.Parse()

	socket := utils.EnvSocketPath("")
	if socket == "" {
		fmt.Println("Can't find any ssh-tpm-agent socket.")
		os.Exit(1)
	}

	lsm.RestrictAdditionalPaths(landlock.RWFiles(socket))

	var ignorefile bool
	var paths []string
	if flag.NArg() == 0 && caURL == "" {
		sshdir := utils.SSHDir()
		paths = []string{
			fmt.Sprintf("%s/id_ecdsa.tpm", sshdir),
			fmt.Sprintf("%s/id_rsa.tpm", sshdir),
		}
		ignorefile = true
	} else {
		paths = flag.Args()
	}

	lsm.RestrictAdditionalPaths(
		// RW on socket
		landlock.RWFiles(socket),
		// RW on files we should encode/decode
		landlock.RWFiles(paths...),
	)

	if err := lsm.Restrict(); err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if caURL != "" && host != "" {
		c := client.NewClient(caURL)
		rwc, err := linuxtpm.Open("/dev/tpmrm0")
		if err != nil {
			log.Fatal(err)
		}
		k, cert, err := c.GetKey(rwc, user, host)
		if err != nil {
			log.Fatal(err)
		}

		sshagentclient := sshagent.NewClient(conn)
		addedkey := sshagent.AddedKey{
			PrivateKey:       k,
			Comment:          k.Description,
			Certificate:      cert,
			ConfirmBeforeUse: confirm,
		}

		_, err = sshagentclient.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&addedkey))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity added from CA authority: %s\n", caURL)
		os.Exit(0)
	}

	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			if ignorefile {
				continue
			}
			log.Fatalf("failed reading TPM key %s: %v", path, err)
		}

		k, err := key.Decode(b)
		if err != nil {
			log.Fatalf("failed decoding TPM key %s: %v", path, err)
		}

		client := sshagent.NewClient(conn)

		if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(
			&sshagent.AddedKey{
				PrivateKey:       k,
				Comment:          k.Description,
				ConfirmBeforeUse: confirm,
			},
		)); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity added: %s (%s)\n", path, k.Description)
		if confirm {
			fmt.Printf("The user must confirm each use of the key\n")
		}

		certStr := fmt.Sprintf("%s-cert.pub", strings.TrimSuffix(path, filepath.Ext(path)))
		if _, err := os.Stat(certStr); !errors.Is(err, os.ErrNotExist) {
			b, err := os.ReadFile(certStr)
			if err != nil {
				log.Fatalf("failed reading certificate %s: %v", certStr, err)
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
			if err != nil {
				log.Fatalf("failed parsing ssh certificate %s: %v", certStr, err)
			}

			cert, ok := pubKey.(*ssh.Certificate)
			if !ok {
				log.Fatalf("failed parsing ssh certificate %s: not a certificate", certStr)
			}
			if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(
				&sshagent.AddedKey{
					PrivateKey:       k,
					Certificate:      cert,
					Comment:          k.Description,
					ConfirmBeforeUse: confirm,
				},
			)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Identity added: %s (%s)\n", certStr, k.Description)
		}

	}
}
