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
    --install-system-units    Installs systemd system units and sshd configs for using
                              ssh-tpm-agent as a hostkey agent.

Display host keys.`

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		installSystemUnits bool
	)

	flag.BoolVar(&installSystemUnits, "install-system-units", false, "install systemd system units")
	flag.Parse()

	if installSystemUnits {
		if err := utils.InstallSystemUnits(); err != nil {
			log.Fatal(err)
		}
		if err := utils.InstallSshdConf(); err != nil {
			log.Printf("didn't install sshd config: %v", err)
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
