package main

import (
	"bytes"
	"crypto"
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

	"log/slog"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	tpmpkix "github.com/foxboron/go-tpm-keyfiles/pkix"
	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"
)

var Version string

const usage = `Usage:
    ssh-tpm-keygen

Options:
    -o, --owner-password        Ask for the owner password.
    -C                          Provide a comment with the key.
    -f                          Output keyfile.
    -N                          passphrase for the key.
    -t ecdsa | rsa              Specify the type of key to create. Defaults to ecdsa
    -b bits                     Number of bits in the key to create.
                                    rsa: 2048 (default)
                                    ecdsa: 256 (default) | 384 | 521
    -I, --import PATH           Import existing key into ssh-tpm-agent.
    -A                          Generate host keys for all key types (rsa and ecdsa).
    --parent-handle             Parent for the TPM key. Can be a hierarchy or a
                                persistent handle.
                                    owner, o (default)
                                    endorment, e
                                    null, n
                                    platform, p
    --print-pubkey              Print the public key given a TPM private key.
    --supported                 List the supported keys of the TPM.
    --wrap PATH                 A SSH key to wrap for import on remote machine.
    --wrap-with PATH            Parent key to wrap the SSH key with.

Generate new TPM sealed keys for ssh-tpm-agent.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in .tpm suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

Example:
    $ ssh-tpm-keygen
    Generating a sealed public/private ecdsa key pair.
    Enter file in which to save the key (/home/user/.ssh/id_ecdsa):
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in /home/user/.ssh/id_ecdsa.tpm
    Your public key has been saved in /home/user/.ssh/id_ecdsa.pub
    The key fingerprint is:
    SHA256:NCMJJ2La+q5tGcngQUQvEOJP3gPH8bMP98wJOEMV564
    The key's randomart image is the color of television, tuned to a dead channel.`

func getPin() ([]byte, error) {
	for {
		pin1, err := askpass.ReadPassphrase("Enter passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			return nil, err
		}
		pin2, err := askpass.ReadPassphrase("Enter same passphrase again: ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pin1, pin2) {
			fmt.Println("Passphrases do not match.  Try again.")
			continue
		}
		return pin1, nil
	}
}

func getOwnerPassword() ([]byte, error) {
	return askpass.ReadPassphrase("Enter owner password: ", askpass.RP_ALLOW_STDIN)
}

func getParentHandle(ph string) (tpm2.TPMHandle, error) {
	switch ph {
	case "endoresement", "e":
		return tpm2.TPMRHEndorsement, nil
	case "null", "n":
		return tpm2.TPMRHNull, nil
	case "plattform", "p":
		return tpm2.TPMRHPlatform, nil
	case "owner", "o":
		fallthrough
	default:
		return tpm2.TPMRHOwner, nil
	}
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
		printPubkey                    string
		parentHandle, wrap, wrapWith   string
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
	flag.StringVar(&keyPin, "N", "", "new passphrase for the key")
	flag.StringVar(&keyType, "t", "ecdsa", "key to create")
	flag.IntVar(&bits, "b", 0, "number of bits")
	flag.StringVar(&importKey, "I", "", "import key")
	flag.StringVar(&importKey, "import", "", "import key")
	flag.BoolVar(&changePin, "p", false, "change passphrase")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&hostKeys, "A", false, "generate host keys")
	flag.BoolVar(&listsupported, "supported", false, "list tpm caps")
	flag.StringVar(&printPubkey, "print-pubkey", "", "print tpm pubkey")
	flag.StringVar(&wrap, "wrap", "", "wrap key")
	flag.StringVar(&wrapWith, "wrap-with", "", "wrap with key")
	flag.StringVar(&parentHandle, "parent-handle", "owner", "parent handle for the key")

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

	supportedECCBitsizes := keyfile.SupportedECCAlgorithms(tpm)

	if printPubkey != "" {
		f, err := os.ReadFile(printPubkey)
		if err != nil {
			log.Fatalf("failed reading TPM key %s: %v", printPubkey, err)
		}

		k, err := key.Decode(f)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(k.AuthorizedKey()))

		os.Exit(0)
	}

	if printPubkey != "" {
		f, err := os.ReadFile(printPubkey)
		if err != nil {
			log.Fatalf("failed reading TPM key %s: %v", printPubkey, err)
		}

		k, err := key.Decode(f)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(k.AuthorizedKey()))
		os.Exit(0)
	}

	if listsupported {
		fmt.Printf("ecdsa bit lengths:")
		for _, alg := range supportedECCBitsizes {
			fmt.Printf(" %d", alg)
		}
		fmt.Println()
		fmt.Println("rsa bit lengths: 2048")
		os.Exit(0)
	}

	// Ask for owner password
	var ownerPassword []byte
	if askOwnerPassword {
		ownerPassword, err = getOwnerPassword()
		if err != nil {
			log.Fatal(err)
		}
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
			"ecdsa": {alg: tpm2.TPMAlgECC, bits: 256},
		}
		for n, t := range lookup {
			filename := fmt.Sprintf("ssh_tpm_host_%s_key", n)
			privatekeyFilename := path.Join(outputPath, filename+".tpm")
			pubkeyFilename := path.Join(outputPath, filename+".pub")

			if utils.FileExists(privatekeyFilename) {
				continue
			}

			slog.Info("Generating new host key", slog.String("algorithm", strings.ToUpper(n)))

			k, err := keyfile.NewLoadableKey(tpm, t.alg, t.bits, ownerPassword,
				keyfile.WithDescription(defaultComment),
			)
			if err != nil {
				log.Fatal(err)
			}

			sshkey := key.SSHTPMKey{TPMKey: k}

			if err := os.WriteFile(pubkeyFilename, sshkey.AuthorizedKey(), 0o600); err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(privatekeyFilename, sshkey.Bytes(), 0o600); err != nil {
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

	// TODO: Support custom handles
	var keyParentHandle tpm2.TPMHandle
	if parentHandle != "" {
		keyParentHandle, err = getParentHandle(parentHandle)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Wrapping of keyfile for import
	if wrap != "" {
		if wrapWith == "" {
			log.Fatal("--wrap needs --wrap-with")
		}
		fmt.Println("Wrapping an existing public/private ecdsa key pair for import.")

		if outputFile == "" {
			log.Fatal("Specify output filename with --output/-o")
		}

		pem, err := os.ReadFile(wrap)
		if err != nil {
			log.Fatal(err)
		}

		wrapperFile, err := os.ReadFile(wrapWith)
		if err != nil {
			log.Fatal(err)
		}

		parentPublic, err := tpmpkix.ToTPMPublic(wrapperFile)
		if err != nil {
			log.Fatalf("wrapper-with does not contain a valid parent TPMTPublic: %v", err)
		}

		var kerr *ssh.PassphraseMissingError
		var rawKey any

		rawKey, err = ssh.ParseRawPrivateKey(pem)
		if errors.As(err, &kerr) {
			for {
				pin, err := askpass.ReadPassphrase("Enter existing passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
				if err != nil {
					log.Fatal(err)
				}
				rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pem, pin)
				if err == nil {
					break
				} else if errors.Is(err, x509.IncorrectPasswordError) {
					fmt.Println("Wrong passphrase, try again.")
					continue
				} else {
					log.Fatal(err)
				}
			}
		}

		// Because go-tpm-keyfiles expects a pointer at some point we deserialize the pointer
		var pk crypto.PrivateKey

		switch key := rawKey.(type) {
		case *ecdsa.PrivateKey:
			if !slices.Contains(supportedECCBitsizes, key.Params().BitSize) {
				log.Fatalf("invalid ecdsa key length: TPM does not support %v bits", key.Params().BitSize)
			}
			pk = *key
		case *rsa.PrivateKey:
			if key.N.BitLen() != 2048 {
				log.Fatal("can only support 2048 bit RSA")
			}
			pk = *key
		default:
			log.Fatal("unsupported key type")
		}

		k, err := keyfile.NewImportablekey(parentPublic, pk,
			keyfile.WithDescription(comment),
			keyfile.WithParent(keyParentHandle),
		)
		if err != nil {
			log.Fatal(err)
		}

		privatekeyFilename = outputFile + ".tpm"
		pubkeyFilename = outputFile + ".pub"

		if err := os.WriteFile(privatekeyFilename, k.Bytes(), 0o600); err != nil {
			log.Fatal(err)
		}

		// Write out the public key
		sshkey := &key.SSHTPMKey{TPMKey: k}
		if err := os.WriteFile(pubkeyFilename, sshkey.AuthorizedKey(), 0o600); err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}

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

		parsedk, err := keyfile.Decode(b)
		if err != nil {
			log.Fatal(err)
		}

		k := &key.SSHTPMKey{TPMKey: parsedk}

		if k.Description != "" {
			fmt.Printf("Key has comment '%s'\n", k.Description)
		}
		if outputFile == "" {
			f, err := askpass.ReadPassphrase(fmt.Sprintf("Enter file in which the key is (%s): ", filename), askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
			if err != nil {
				log.Fatal(err)
			}
			filename = string(f)
		}

		oldPin, err := askpass.ReadPassphrase("Enter old passphrase: ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			log.Fatal(err)
		}
		newPin, err := askpass.ReadPassphrase("Enter new passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			log.Fatal(err)
		}
		newPin2, err := askpass.ReadPassphrase("Enter same passphrase: ", askpass.RP_ALLOW_STDIN)
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(newPin, newPin2) {
			log.Fatal("Passphrases do not match. Try again.")
		}
		fmt.Println()

		if err := keyfile.ChangeAuth(tpm, ownerPassword, k.TPMKey, oldPin, newPin); err != nil {
			log.Fatal("Failed changing passphrase on the key.")
		}

		if err := os.WriteFile(filename, k.Bytes(), 0o600); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Your identification has been saved with the new passphrase.")
		os.Exit(0)
	}

	// Only used with -I/--import
	var toImportKey any

	var wrappedKey bool
	var pem []byte

	if importKey != "" {
		pem, err = os.ReadFile(importKey)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := keyfile.Decode(pem); !errors.Is(err, keyfile.ErrNotTPMKey) {
			wrappedKey = true
			if outputFile == "" {
				log.Fatal("Specify output filename with --output/-o")
			}
			filename = outputFile
		} else {
			fmt.Println("Sealing an existing public/private key pair.")

			if outputFile == "" {
				filename = importKey
			}

			var kerr *ssh.PassphraseMissingError

			var rawKey any

			rawKey, err = ssh.ParseRawPrivateKey(pem)
			if errors.As(err, &kerr) {
				for {
					pin, err := askpass.ReadPassphrase("Enter existing passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
					if err != nil {
						log.Fatal(err)
					}
					rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pem, pin)
					if err == nil {
						break
					} else if errors.Is(err, x509.IncorrectPasswordError) {
						fmt.Println("Wrong passphrase, try again.")
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
		}
	} else {
		fmt.Printf("Generating a sealed public/private %s key pair.\n", keyType)
		if outputFile == "" {
			f, err := askpass.ReadPassphrase(fmt.Sprintf("Enter file in which to save the key (%s): ", filename), askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
			if err != nil {
				log.Fatal(err)
			}
			filenameInput := string(f)
			if filenameInput != "" {
				filename = strings.TrimSuffix(filenameInput, ".tpm")
			}
		} else {
			filename = outputFile
		}
	}

	privatekeyFilename = filename + ".tpm"
	pubkeyFilename = filename + ".pub"

	if utils.FileExists(privatekeyFilename) {
		fmt.Printf("%s already exists.\n", privatekeyFilename)
		s, err := askpass.ReadPassphrase("Overwrite (y/n)? ", askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(s, []byte("y")) {
			return
		}
	}

	if utils.FileExists(pubkeyFilename) {
		fmt.Printf("%s already exists.\n", pubkeyFilename)
		s, err := askpass.ReadPassphrase("Overwrite (y/n)? ", askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(s, []byte("y")) {
			return
		}
	}

	var pin []byte
	if wrappedKey {
		// TODO: Need to structure this code better
	} else if keyPin != "" {
		pin = []byte(keyPin)
	} else {
		pinInput, err := getPin()
		if err != nil {
			log.Fatal(err)
		}
		if bytes.Equal(pin, []byte("")) {
			pin = []byte(pinInput)
		}
	}

	var k *key.SSHTPMKey

	if wrappedKey {
		fmt.Println("Importing a wrapped public/private key pair.")
		tpmkey, err := keyfile.Decode(pem)
		if errors.Is(err, keyfile.ErrNotTPMKey) {
			log.Fatal("This shouldnt happen")
		}
		tkey, err := keyfile.ImportTPMKey(tpm, tpmkey, ownerPassword)
		if err != nil {
			log.Fatal(err)
		}
		k = &key.SSHTPMKey{TPMKey: tkey}
		importKey = ""
	} else if importKey != "" {
		k, err = key.NewImportedSSHTPMKey(tpm, toImportKey, ownerPassword,
			keyfile.WithParent(keyParentHandle),
			keyfile.WithUserAuth(pin),
			keyfile.WithDescription(comment))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		k, err = key.NewSSHTPMKey(tpm, tpmkeyType, bits, ownerPassword,
			keyfile.WithParent(keyParentHandle),
			keyfile.WithDescription(defaultComment),
			keyfile.WithUserAuth(pin),
			keyfile.WithDescription(comment),
		)
		if err != nil {
			log.Fatal(err)
		}
	}

	if importKey == "" {
		if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
			log.Fatal(err)
		}
	}

	if err := os.WriteFile(privatekeyFilename, k.Bytes(), 0o600); err != nil {
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
