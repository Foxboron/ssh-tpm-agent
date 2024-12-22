package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/foxboron/ssh-tpm-agent/utils"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var Version string

const usage = `Usage:
    ssh-tpm-hostkeys
    ssh-tpm-hostkeys --install-system-units

Options:
    --install-system-units    Installs systemd system units for using ssh-tpm-agent 
                              as a hostkey agent.
    --install-sshd-config     Installs sshd configuration for the ssh-tpm-agent socket.

Display host keys.`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		installSystemUnits bool
		installSshdConfig  bool
	)

	flag.BoolVar(&installSystemUnits, "install-system-units", false, "install systemd system units")
	flag.BoolVar(&installSshdConfig, "install-sshd-config", false, "install sshd config")
	flag.Parse()

	if installSystemUnits {
		if err := utils.InstallHostkeyUnits(); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Enable with: systemctl enable --now ssh-tpm-agent.socket")
		os.Exit(0)
	}
	if installSshdConfig {
		if err := utils.InstallSshdConf(); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	socket := "/var/tmp/ssh-tpm-agent.sock"
	if socket == "" {
		fmt.Println("Can't find any ssh-tpm-agent socket.")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := sshagent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		log.Fatal(err)
	}

	for _, k := range keys {
		fmt.Println(k.String())
	}
}
