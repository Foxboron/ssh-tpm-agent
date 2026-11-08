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
	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var Version string

const usage = `Usage:
    ssh-tpm-add [-c] [-t LIFE] [--cache-timeout DURATION] [FILE ...]

Options:
    -c                     Require confirmation via SSH_ASKPASS before each
                           use of the key for signing.

    -t LIFE                Remove added keys after LIFE. Examples: 300, 5m, 1h.

    --cache-timeout DUR    Expire this key's cached PIN after DUR of inactivity.
                           Examples: 30s, 5m, 1h.

Add a sealed TPM key to ssh-tpm-agent. Allows CA key provisioning with the --ca
option.

Example:
    $ ssh-tpm-add id_rsa.tpm`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var caURL, host, user, lifetime, cacheTimeout string
	var confirm bool
	var lifetimeSecs, cacheTimeoutSecs uint32

	flag.StringVar(&caURL, "ca", "", "ca authority")
	flag.StringVar(&host, "host", "", "ssh hot")
	flag.StringVar(&user, "user", "", "remote ssh user")
	flag.BoolVar(&confirm, "c", false, "require confirmation before each use")
	flag.StringVar(&lifetime, "t", "", "maximum lifetime of added keys")
	flag.StringVar(&cacheTimeout, "cache-timeout", "", "expire cached PIN after inactivity")
	flag.Parse()
	var lifetimeSet, cacheTimeoutSet bool
	flag.Visit(func(f *flag.Flag) {
		lifetimeSet = lifetimeSet || f.Name == "t"
		cacheTimeoutSet = cacheTimeoutSet || f.Name == "cache-timeout"
	})
	if lifetimeSet {
		var err error
		lifetimeSecs, err = parseLifetime(lifetime)
		if err != nil {
			log.Fatalf("invalid -t lifetime: %v", err)
		}
	}
	if cacheTimeoutSet {
		var err error
		cacheTimeoutSecs, err = parseLifetime(cacheTimeout)
		if err != nil {
			log.Fatalf("invalid --cache-timeout duration: %v", err)
		}
	}

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

		if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsgWithOptions(
			&sshagent.AddedKey{
				PrivateKey:       k,
				Comment:          k.Description,
				LifetimeSecs:     lifetimeSecs,
				ConfirmBeforeUse: confirm,
			}, lifetimeSet, cacheTimeoutSecs, cacheTimeoutSet)); err != nil {
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
			if _, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsgWithOptions(
				&sshagent.AddedKey{
					PrivateKey:       k,
					Certificate:      cert,
					Comment:          k.Description,
					LifetimeSecs:     lifetimeSecs,
					ConfirmBeforeUse: confirm,
				}, lifetimeSet, cacheTimeoutSecs, cacheTimeoutSet)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Identity added: %s (%s)\n", certStr, k.Description)
		}

	}
}
