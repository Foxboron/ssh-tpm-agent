package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"golang.org/x/crypto/ssh"
)

var Version string

const usage = `Usage:
    ssh-tpm-keygen

Options:
    -C       Comment WIP
    -f       Output keyfile WIP
    -N       PIN for the key WIP

Generate new sealed keys for ssh-tpm-agent.`

func GetSSHDir() string {
	dirname, err := os.UserHomeDir()
	if err != nil {
		panic("$HOME is not defined")
	}
	return path.Join(dirname, ".ssh")
}

func getStdin(s string, args ...any) (string, error) {
	fmt.Printf(s, args...)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func getPin() []byte {
	for {
		pin1, err := getStdin("Enter pin (empty for no pin): ")
		if err != nil {
			log.Fatal(err)
		}

		pin2, err := getStdin("Enter same pin again: ")
		if err != nil {
			log.Fatal(err)
		}
		if pin1 != pin2 {
			fmt.Println("Passphrases do not match.  Try again.")
			continue
		}
		return []byte(pin1)
	}
}

func fileExists(s string) bool {
	info, err := os.Stat(s)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return !info.IsDir()
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		comment, outputFile, keyPin string
		swtpmFlag                   bool
	)

	flag.StringVar(&comment, "C", "", "provide a comment with the key")
	flag.StringVar(&outputFile, "f", "", "output keyfile")
	flag.StringVar(&keyPin, "N", "", "new pin for the key")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")

	flag.Parse()

	fmt.Println("Generating a sealed public/private ecdsa key pair.")

	filename := path.Join(GetSSHDir(), "id_ecdsa")
	filenameInput, err := getStdin("Enter file in which to save the key (%s): ", filename)
	if err != nil {
		log.Fatal(err)
	}
	if filenameInput != "" {
		filename = filenameInput
	}

	privatekeyFilename := filename + ".tpm"

	if fileExists(privatekeyFilename) {
		fmt.Printf("%s already exists.\n", privatekeyFilename)
		s, err := getStdin("Overwrite (y/n)?")
		if err != nil {
			log.Fatal(err)
		}
		if s != "y" {
			return
		}
	}

	var pin []byte
	pinInput := getPin()
	if bytes.Equal(pin, []byte("")) {
		pin = []byte(pinInput)
	}

	tpm, err := utils.GetTPM(swtpmFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()
	k, err := key.CreateKey(tpm, pin)
	if err != nil {
		log.Fatal(err)
	}

	sshKey, err := k.SSHPublicKey()
	if err != nil {
		log.Fatal(err)
	}
	pubkeyFilename := filename + ".pub"
	if err := os.WriteFile(pubkeyFilename, ssh.MarshalAuthorizedKey(sshKey), 0644); err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(privatekeyFilename, key.MarshalKey(k), 0600); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Your identification has been saved in %s\n", privatekeyFilename)
	fmt.Printf("Your public key has been saved in %s\n", pubkeyFilename)
	fmt.Printf("The key fingerprint is:\n")
	fmt.Println(ssh.FingerprintSHA256(sshKey))
	fmt.Println("The key's randomart image is the color of television, tuned to a dead channel.")
}
