package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"strings"
	"syscall"

	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slog"
	"golang.org/x/term"
)

var Version string

const usage = `Usage:
    ssh-tpm-keygen

Options:
    -C                          Provide a comment with the key.
    -f                          Output keyfile.
    -N                          PIN for the key.
    -t ecdsa | rsa              Specify the type of key to create. Defaults to ecdsa
    -I, --import PATH           Import existing key into ssh-tpm-agent.
    -A                          Generate host keys for all key types (rsa and ecdsa).

Generate new TPM sealed keys for ssh-tpm-agent.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in .tpm suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

Example:
    $ ssh-tpm-keygen
    Generating a sealed public/private ecdsa key pair.
    Enter file in which to save the key (/home/user/.ssh/id_ecdsa):
    Enter pin (empty for no pin):
    Enter same pin again:
    Your identification has been saved in /home/user/.ssh/id_ecdsa.tpm
    Your public key has been saved in /home/user/.ssh/id_ecdsa.pub
    The key fingerprint is:
    SHA256:NCMJJ2La+q5tGcngQUQvEOJP3gPH8bMP98wJOEMV564
    The key's randomart image is the color of television, tuned to a dead channel.`

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
		fmt.Printf("Enter pin (empty for no pin): ")
		pin1, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Confirm pin: ")
		pin2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println("")
		if err != nil {
			log.Fatal(err)
		}

		if !bytes.Equal(pin1, pin2) {
			fmt.Println("Passphrases do not match.  Try again.")
			continue
		}
		return pin1
	}
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		comment, outputFile, keyPin string
		keyType, importKey          string
		swtpmFlag, hostKeys         bool
	)

	defaultComment := func() string {
		user, err := user.Current()
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
			return ""
		}
		host, err := os.Hostname()
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
			return ""
		}
		return user.Username + "@" + host
	}()

	flag.StringVar(&comment, "C", defaultComment, "provide a comment, default to user@host")
	flag.StringVar(&outputFile, "f", "", "output keyfile")
	flag.StringVar(&keyPin, "N", "", "new pin for the key")
	flag.StringVar(&keyType, "t", "ecdsa", "key to create")
	flag.StringVar(&importKey, "I", "", "import key")
	flag.StringVar(&importKey, "import", "", "import key")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&hostKeys, "A", false, "generate host keys")

	flag.Parse()

	tpm, err := utils.TPM(swtpmFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	// Generate host keys
	if hostKeys {
		// Mimics the `ssh-keygen -A -f ./something` behaviour
		outputPath := "/etc/ssh"
		if outputFile != "" {
			outputPath = path.Join(outputFile, outputPath)
		}

		lookup := map[string]tpm2.TPMAlgID{
			"rsa":   tpm2.TPMAlgRSA,
			"ecdsa": tpm2.TPMAlgECDSA,
		}
		for n, t := range lookup {
			filename := fmt.Sprintf("ssh_tpm_host_%s_key", n)
			privatekeyFilename := path.Join(outputPath, filename+".tpm")
			pubkeyFilename := path.Join(outputPath, filename+".pub")

			if utils.FileExists(privatekeyFilename) {
				continue
			}

			slog.Info(fmt.Sprintf("Generating new %s host key\n", strings.ToUpper(n)))

			k, err := key.CreateKey(tpm, t, []byte(""), []byte(defaultComment))
			if err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(privatekeyFilename, k.Encode(), 0o600); err != nil {
				log.Fatal(err)
			}

			slog.Info(fmt.Sprintf("Wrote %s\n", privatekeyFilename))
		}
		os.Exit(0)
	}

	var tpmkeyType tpm2.TPMAlgID
	var filename string
	var privatekeyFilename string
	var pubkeyFilename string

	switch keyType {
	case "ecdsa":
		tpmkeyType = tpm2.TPMAlgECDSA
		filename = "id_ecdsa"
	case "rsa":
		tpmkeyType = tpm2.TPMAlgRSA
		filename = "id_rsa"
	}

	if outputFile != "" {
		filename = outputFile
	}

	// Only used with -I/--import
	var toImportKey any

	if importKey != "" {
		fmt.Println("Sealing an existing public/private ecdsa key pair.")

		filename = importKey

		pem, err := os.ReadFile(importKey)
		if err != nil {
			log.Fatal(err)
		}

		var kerr *ssh.PassphraseMissingError

		var rawKey any

		rawKey, err = ssh.ParseRawPrivateKey(pem)
		if errors.As(err, &kerr) {
			for {
				fmt.Printf("Enter existing password (empty for no pin): ")
				pin, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println("")
				if err != nil {
					log.Fatal(err)
				}
				rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pem, pin)
				if err == nil {
					break
				} else if errors.Is(err, x509.IncorrectPasswordError) {
					fmt.Println("Wrong password, try again.")
					continue
				} else {
					log.Fatal(err)
				}
			}
		}

		switch key := rawKey.(type) {
		case *ecdsa.PrivateKey:
			toImportKey = *key
		case *rsa.PrivateKey:
			if key.N.BitLen() != 2048 {
				log.Fatal("can only support 2048 bit RSA")
			}
			toImportKey = *key
		default:
			log.Fatal("unsupported key type")
		}

		pubPem, err := os.ReadFile(importKey + ".pub")
		if err != nil {
			log.Fatalf("can't find corresponding public key: %v", err)
		}

		_, c, _, _, err := ssh.ParseAuthorizedKey(pubPem)
		if err != nil {
			log.Fatal("can't parse public key", err)
		}
		comment = c

	} else {
		fmt.Printf("Generating a sealed public/private %s key pair.\n", keyType)

		filename = path.Join(utils.SSHDir(), filename)
		filenameInput, err := getStdin("Enter file in which to save the key (%s): ", filename)
		if err != nil {
			log.Fatal(err)
		}
		if filenameInput != "" {
			filename = filenameInput
		}

	}

	privatekeyFilename = filename + ".tpm"
	pubkeyFilename = filename + ".pub"

	if utils.FileExists(privatekeyFilename) {
		fmt.Printf("%s already exists.\n", privatekeyFilename)
		s, err := getStdin("Overwrite (y/n)?")
		if err != nil {
			log.Fatal(err)
		}
		if s != "y" {
			return
		}
	}

	if utils.FileExists(pubkeyFilename) {
		fmt.Printf("%s already exists.\n", pubkeyFilename)
		s, err := getStdin("Overwrite (y/n)?")
		if err != nil {
			log.Fatal(err)
		}
		if s != "y" {
			return
		}
	}

	var pin []byte
	if keyPin != "" {
		pin = []byte(keyPin)
	} else {
		pinInput := getPin()
		if bytes.Equal(pin, []byte("")) {
			pin = []byte(pinInput)
		}
	}

	var k *key.Key

	if importKey != "" {
		// TODO: Read public key for comment
		k, err = key.ImportKey(tpm, toImportKey, pin, []byte(comment))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		k, err = key.CreateKey(tpm, tpmkeyType, pin, []byte(comment))
		if err != nil {
			log.Fatal(err)
		}
	}

	if importKey == "" {
		if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
			log.Fatal(err)
		}
	}

	if err := os.WriteFile(privatekeyFilename, k.Encode(), 0o600); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Your identification has been saved in %s\n", privatekeyFilename)
	if importKey == "" {
		fmt.Printf("Your public key has been saved in %s\n", pubkeyFilename)
	}
	fmt.Printf("The key fingerprint is:\n")
	fmt.Println(k.Fingerprint())
	fmt.Println("The key's randomart image is the color of television, tuned to a dead channel.")
}
