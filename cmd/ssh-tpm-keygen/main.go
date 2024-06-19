package main

import (
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
	"slices"
	"strings"

	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slog"
)

var Version string

const usage = `Usage:
    ssh-tpm-keygen

Options:
    -o, --owner-password        Ask for the owner password.
    -C                          Provide a comment with the key.
    -f                          Output keyfile.
    -N                          PIN for the key.
    -t ecdsa | rsa              Specify the type of key to create. Defaults to ecdsa
    -b bits                     Number of bits in the key to create.
                                    rsa: 2048 (default)
                                    ecdsa: 256 (default) | 384 | 521
    -I, --import PATH           Import existing key into ssh-tpm-agent.
    -A                          Generate host keys for all key types (rsa and ecdsa).
    --supported                 List the supported keys of the TPM.

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

func getPin() []byte {
	for {
		pin1 := askpass.ReadPassphrase("Enter pin (empty for no pin): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		pin2 := askpass.ReadPassphrase("Confirm pin: ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		fmt.Println(pin1)
		fmt.Println(pin2)
		if !bytes.Equal(pin1, pin2) {
			fmt.Println("Passphrases do not match.  Try again.")
			continue
		}
		return pin1
	}
}

func getOwnerPassword() []byte {
	return askpass.ReadPassphrase("Enter owner password: ", askpass.RP_ALLOW_STDIN)
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		askOwnerPassword               bool
		comment, outputFile, keyPin    string
		keyType, importKey             string
		bits                           int
		swtpmFlag, hostKeys, changePin bool
		listsupported                  bool
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

	flag.BoolVar(&askOwnerPassword, "o", false, "ask for the owner password")
	flag.BoolVar(&askOwnerPassword, "owner-password", false, "ask for the owner password")
	flag.StringVar(&comment, "C", defaultComment, "provide a comment, default to user@host")
	flag.StringVar(&outputFile, "f", "", "output keyfile")
	flag.StringVar(&keyPin, "N", "", "new pin for the key")
	flag.StringVar(&keyType, "t", "ecdsa", "key to create")
	flag.IntVar(&bits, "b", 0, "number of bits")
	flag.StringVar(&importKey, "I", "", "import key")
	flag.StringVar(&importKey, "import", "", "import key")
	flag.BoolVar(&changePin, "p", false, "change pin")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&hostKeys, "A", false, "generate host keys")
	flag.BoolVar(&listsupported, "supported", false, "list tpm caps")

	flag.Parse()

	tpm, err := utils.TPM(swtpmFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	if bits == 0 {
		if keyType == "ecdsa" {
			bits = 256
		}
		if keyType == "rsa" {
			bits = 2048
		}
	}

	supportedECCBitsizes := key.SupportedECCAlgorithms(tpm)

	if listsupported {
		fmt.Printf("ecdsa bit lengths:")
		for _, alg := range key.SupportedECCAlgorithms(tpm) {
			fmt.Printf(" %d", alg)
		}
		fmt.Println()
		fmt.Println("rsa bit lengths: 2048")
		os.Exit(0)
	}

	// Ask for owner password
	var ownerPassword []byte
	if askOwnerPassword {
		ownerPassword = getOwnerPassword()
	} else {
		ownerPassword = []byte("")
	}

	// Generate host keys
	if hostKeys {
		// Mimics the `ssh-keygen -A -f ./something` behaviour
		outputPath := "/etc/ssh"
		if outputFile != "" {
			outputPath = path.Join(outputFile, outputPath)
		}

		lookup := map[string]struct {
			alg  tpm2.TPMAlgID
			bits int
		}{
			"rsa":   {alg: tpm2.TPMAlgRSA, bits: 2048},
			"ecdsa": {alg: tpm2.TPMAlgECDSA, bits: 256},
		}
		for n, t := range lookup {
			filename := fmt.Sprintf("ssh_tpm_host_%s_key", n)
			privatekeyFilename := path.Join(outputPath, filename+".tpm")
			pubkeyFilename := path.Join(outputPath, filename+".pub")

			if utils.FileExists(privatekeyFilename) {
				continue
			}

			slog.Info("Generating new host key", slog.String("algorithm", strings.ToUpper(n)))

			k, err := key.CreateKey(tpm, t.alg, t.bits, ownerPassword, []byte(""), defaultComment)
			if err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
				log.Fatal(err)
			}
			encodedkey, err := k.Encode()
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(privatekeyFilename, encodedkey, 0o600); err != nil {
				log.Fatal(err)
			}

			slog.Info("Wrote private key", slog.String("filename", privatekeyFilename))
		}
		os.Exit(0)
	}

	var tpmkeyType tpm2.TPMAlgID
	var filename string
	var privatekeyFilename string
	var pubkeyFilename string

	switch keyType {
	case "ecdsa":
		tpmkeyType = tpm2.TPMAlgECC
		filename = "id_ecdsa"

		if !slices.Contains(supportedECCBitsizes, bits) {
			log.Fatalf("invalid ecdsa key length: TPM does not support %v bits", bits)
		}

	case "rsa":
		tpmkeyType = tpm2.TPMAlgRSA
		filename = "id_rsa"
	}

	if outputFile != "" {
		filename = outputFile
	} else {
		filename = path.Join(utils.SSHDir(), filename)
	}

	if changePin {
		b, err := os.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		k, err := key.DecodeKey(b)
		if err != nil {
			log.Fatal(err)
		}
		if k.Description() != "" {
			fmt.Printf("Key has comment '%s'\n", k.Description())
		}
		if outputFile == "" {
			filename = string(askpass.ReadPassphrase(fmt.Sprintf("Enter file in which the key is (%s): ", filename), askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON))
		}

		oldPin := askpass.ReadPassphrase("Enter old pin: ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		newPin := askpass.ReadPassphrase("Enter new pin (empty for no pin): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		newPin2 := askpass.ReadPassphrase("Enter same pin: ", askpass.RP_ALLOW_STDIN)
		if !bytes.Equal(newPin, newPin2) {
			log.Fatal("Pin do not match. Try again.")
		}
		fmt.Println()

		newkey, err := key.ChangeAuth(tpm, ownerPassword, k, oldPin, newPin)
		if err != nil {
			log.Fatal("Failed changing pin on the key.")
		}

		encodedkey, err := newkey.Encode()
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile(filename, encodedkey, 0o600); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Your identification has been saved with the new pin.")
		os.Exit(0)
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
				pin := askpass.ReadPassphrase("Enter existing password (empty for no pin): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
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
			if !slices.Contains(supportedECCBitsizes, key.Params().BitSize) {
				log.Fatalf("invalid ecdsa key length: TPM does not support %v bits", key.Params().BitSize)
			}
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
		filenameInput := string(askpass.ReadPassphrase(fmt.Sprintf("Enter file in which to save the key (%s): ", filename), askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON))
		if filenameInput != "" {
			filename = strings.TrimSuffix(filenameInput, ".tpm")
		}
	}

	privatekeyFilename = filename + ".tpm"
	pubkeyFilename = filename + ".pub"

	if utils.FileExists(privatekeyFilename) {
		fmt.Printf("%s already exists.\n", privatekeyFilename)
		s := askpass.ReadPassphrase("Overwrite (y/n)? ", askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if !bytes.Equal(s, []byte("y")) {
			return
		}
	}

	if utils.FileExists(pubkeyFilename) {
		fmt.Printf("%s already exists.\n", pubkeyFilename)
		s := askpass.ReadPassphrase("Overwrite (y/n)? ", askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if !bytes.Equal(s, []byte("y")) {
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
		k, err = key.ImportKey(tpm, ownerPassword, toImportKey, pin, comment)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		k, err = key.CreateKey(tpm, tpmkeyType, bits, ownerPassword, pin, comment)
		if err != nil {
			log.Fatal(err)
		}
	}

	if importKey == "" {
		if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
			log.Fatal(err)
		}
	}

	encodedkey, err := k.Encode()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(privatekeyFilename, encodedkey, 0o600); err != nil {
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
