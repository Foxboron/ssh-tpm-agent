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
	"log/slog"
	"os"
	"os/user"
	"path"
	"slices"
	"strings"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	tpmpkix "github.com/foxboron/go-tpm-keyfiles/pkix"
	"github.com/foxboron/ssh-tpm-agent/askpass"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

var Version string

const usage = `Usage:
    ssh-tpm-keygen
    ssh-tpm-keygen --wrap keyfile --wrap-with keyfile
    ssh-tpm-keygen --import keyfile
    ssh-tpm-keygen --print-pubkey keyfile
    ssh-tpm-keygen --supported
    ssh-tpm-keygen -p [-f keyfile] [-N new_passphrase] [-P old_passphrase]
    ssh-tpm-keygen -A [-f path] [--hierarchy hierarchy]

Options:
    -o, --owner-password   Ask for the owner password.
    -C                     Provide a comment with the key.
    -f                     Output keyfile.
    -N                     passphrase for the key.
    -t ecdsa | rsa         Specify the type of key to create. Defaults to ecdsa
    -b bits                Number of bits in the key to create.
                               rsa: 2048 (default)
                               ecdsa: 256 (default) | 384 | 521
    -p                     Change keyfile passphrase
    -P                     Old passphrase for keyfile
    -I, --import PATH      Import existing key into ssh-tpm-agent.
    -A                     Generate host keys for all key types (rsa and ecdsa).
    --hierarchy HIERARCHY  Hierarchy to create the persistent public key under.
                           Only useable with -A.
                               owner, o (default)
                               endorsement, e
                               null, n
                               platform, p
    --parent-handle        Parent for the TPM key. Can be a hierarchy or a
                           persistent handle.
                               owner, o (default)
                               endorsement, e
                               null, n
                               platform, p
    --print-pubkey         Print the public key given a TPM private key.
    --supported            List the supported keys of the TPM.
    --wrap PATH            A SSH key to wrap for import on remote machine.
    --wrap-with PATH       Parent key to wrap the SSH key with.

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

func doHostKeys(tpm transport.TPMCloser, outputFile string, ownerPassword []byte, hierarchy string) {
	// Mimics the `ssh-keygen -A -f ./something` behaviour
	outputPath := "/etc/ssh"
	if outputFile != "" {
		outputPath = path.Join(outputFile, outputPath)
	}

	for n, t := range map[string]struct {
		alg  tpm2.TPMAlgID
		bits int
	}{
		"rsa":   {alg: tpm2.TPMAlgRSA, bits: 2048},
		"ecdsa": {alg: tpm2.TPMAlgECC, bits: 256},
	} {
		filename := fmt.Sprintf("ssh_tpm_host_%s_key", n)
		privatekeyFilename := path.Join(outputPath, filename+".tpm")
		pubkeyFilename := path.Join(outputPath, filename+".pub")

		if utils.FileExists(privatekeyFilename) || utils.FileExists(pubkeyFilename) {
			continue
		}

		if hierarchy != "" {
			slog.Info("Generating new hierarcy host key", slog.String("algorithm", strings.ToUpper(n)), slog.String("hierarchy", hierarchy))
			h, err := utils.GetParentHandle(hierarchy)
			if err != nil {
				log.Fatal(err)
			}
			hkey, err := key.CreateHierarchyKey(tpm, t.alg, h, defaultComment())
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(pubkeyFilename, hkey.AuthorizedKey(), 0o600); err != nil {
				log.Fatal(err)
			}
			slog.Info("Wrote public key", slog.String("filename", pubkeyFilename))
		} else {
			slog.Info("Generating new host key", slog.String("algorithm", strings.ToUpper(n)))
			k, err := keyfile.NewLoadableKey(tpm, t.alg, t.bits, ownerPassword,
				keyfile.WithDescription(defaultComment()),
			)
			if err != nil {
				log.Fatal(err)
			}

			sshkey, err := key.WrapTPMKey(k)
			if err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(pubkeyFilename, sshkey.AuthorizedKey(), 0o600); err != nil {
				log.Fatal(err)
			}

			if err := os.WriteFile(privatekeyFilename, sshkey.Bytes(), 0o600); err != nil {
				log.Fatal(err)
			}
			slog.Info("Wrote private key", slog.String("filename", privatekeyFilename))
		}
	}
}

func doChangePin(tpm transport.TPMCloser, passphrase, keyPin, ownerPassword []byte, filename, outputFile string) error {
	filename = filename + ".tpm"
	if outputFile != "" {
		filename = outputFile
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	k, err := key.Decode(b)
	if err != nil {
		return err
	}

	if k.Description != "" {
		fmt.Printf("Key has comment '%s'\n", k.Description)
	}
	if outputFile == "" {
		f, err := askpass.ReadPassphrase(fmt.Sprintf("Enter file in which the key is (%s): ", filename), askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if err != nil {
			return err
		}
		filename = string(f)
	}

	if len(passphrase) == 0 {
		passphrase, err = askpass.ReadPassphrase("Enter old passphrase: ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			return err
		}
	}

	if len(keyPin) == 0 {
		keyPin, err = askpass.ReadPassphrase("Enter new passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
		if err != nil {
			return err
		}
		newPin, err := askpass.ReadPassphrase("Enter same passphrase: ", askpass.RP_ALLOW_STDIN)
		if err != nil {
			return err
		}
		if !bytes.Equal(keyPin, newPin) {
			log.Fatal("Passphrases do not match. Try again.")
		}
		fmt.Println()
	}

	if err := keyfile.ChangeAuth(tpm, ownerPassword, k.TPMKey, keyPin, passphrase); err != nil {
		log.Fatal("Failed changing passphrase on the key.")
	}

	if err := os.WriteFile(filename, k.Bytes(), 0o600); err != nil {
		return err
	}

	fmt.Println("Your identification has been saved with the new passphrase.")
	return nil
}

func doWrapWith(supportedECCBitsizes []int, wrap, wrapWith string, keyParentHandle tpm2.TPMHandle, comment, outputFile string) {
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

	fmt.Println("Wrapping an existing public/private ecdsa key pair for import.")

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

	privatekeyFilename := outputFile + ".tpm"
	pubkeyFilename := outputFile + ".pub"

	if err := os.WriteFile(privatekeyFilename, k.Bytes(), 0o600); err != nil {
		log.Fatal(err)
	}

	// Write out the public key
	sshkey, err := key.WrapTPMKey(k)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(pubkeyFilename, sshkey.AuthorizedKey(), 0o600); err != nil {
		log.Fatal(err)
	}
}

func defaultComment() string {
	cache.Do(func() {
		cache.u, cache.err = user.Current()
		if cache.err != nil {
			return
		}
		cache.host, cache.err = os.Hostname()
	})
	if cache.err != nil {
		slog.Error(cache.err.Error())
		os.Exit(1)
		return ""
	}
	return cache.u.Username + "@" + cache.host
}

var cache struct {
	sync.Once
	u    *user.User
	host string
	err  error
}

var eccBitCache struct {
	sync.Once
	bits []int
}

func supportedECCBitsizes(tpm transport.TPMCloser) []int {
	eccBitCache.Do(func() {
		eccBitCache.bits = keyfile.SupportedECCAlgorithms(tpm)
	})
	return eccBitCache.bits
}

func checkFile(f string) error {
	if utils.FileExists(f) {
		fmt.Printf("%s already exists.\n", f)
		s, err := askpass.ReadPassphrase("Overwrite (y/n)? ", askpass.RP_ALLOW_STDIN|askpass.RPP_ECHO_ON)
		if err != nil {
			return err
		}
		if !bytes.Equal(s, []byte("y")) {
			return nil
		}
	}
	return nil
}

func doImportKey(tpm transport.TPMCloser, keyParentHandle tpm2.TPMHandle, ownerPassword []byte, keyPin string, pem []byte, filename string) (*key.SSHTPMKey, error) {
	var toImportKey any
	var kerr *ssh.PassphraseMissingError
	var rawKey any
	var err error

	rawKey, err = ssh.ParseRawPrivateKey(pem)
	if errors.As(err, &kerr) {
		for {
			pin, err := askpass.ReadPassphrase("Enter existing passphrase (empty for no passphrase): ", askpass.RP_ALLOW_STDIN|askpass.RP_NEWLINE)
			if err != nil {
				return nil, err
			}
			rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pem, pin)
			if err == nil {
				break
			} else if errors.Is(err, x509.IncorrectPasswordError) {
				fmt.Println("Wrong passphrase, try again.")
				continue
			} else {
				return nil, err
			}
		}
	}

	switch key := rawKey.(type) {
	case *ecdsa.PrivateKey:
		toImportKey = *key
		if !slices.Contains(supportedECCBitsizes(tpm), key.Params().BitSize) {
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

	pubPem, err := os.ReadFile(filename + ".pub")
	if err != nil {
		log.Fatalf("can't find corresponding public key: %v", err)
	}
	_, comment, _, _, err := ssh.ParseAuthorizedKey(pubPem)
	if err != nil {
		log.Fatal("can't parse public key", err)
	}

	var pin []byte
	if keyPin != "" {
		pin = []byte(keyPin)
	} else {
		pinInput, err := getPin()
		if err != nil {
			log.Fatal(err)
		}
		pin = []byte(pinInput)
	}

	k, err := key.NewImportedSSHTPMKey(tpm, toImportKey, ownerPassword,
		keyfile.WithParent(keyParentHandle),
		keyfile.WithUserAuth(pin),
		keyfile.WithDescription(comment))
	if err != nil {
		return nil, err
	}
	return k, nil
}

func doImportWrappedKey(tpm transport.TPMCloser, ownerPassword, pem []byte) (*key.SSHTPMKey, error) {
	tpmkey, err := keyfile.Decode(pem)
	if errors.Is(err, keyfile.ErrNotTPMKey) {
		log.Fatal("This shouldnt happen")
	}
	tkey, err := keyfile.ImportTPMKey(tpm, tpmkey, ownerPassword)
	if err != nil {
		return nil, err
	}
	k, err := key.WrapTPMKey(tkey)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func doCreateSSHKey(tpm transport.TPMCloser, ownerPassword []byte, keyPin string, keyParentHandle tpm2.TPMHandle, keyType string, comment string, bits int) (*key.SSHTPMKey, error) {
	var tpmkeyType tpm2.TPMAlgID
	switch keyType {
	case "ecdsa":
		tpmkeyType = tpm2.TPMAlgECC
	case "rsa":
		tpmkeyType = tpm2.TPMAlgRSA
	}

	var pin []byte
	if keyPin != "" {
		pin = []byte(keyPin)
	} else {
		pinInput, err := getPin()
		if err != nil {
			log.Fatal(err)
		}
		pin = []byte(pinInput)
	}

	k, err := key.NewSSHTPMKey(tpm, tpmkeyType, bits, ownerPassword,
		keyfile.WithParent(keyParentHandle),
		keyfile.WithUserAuth(pin),
		keyfile.WithDescription(comment),
	)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		askOwnerPassword                        bool
		comment, outputFile, keyPin, passphrase string
		keyType, importKey                      string
		bits                                    int
		swtpmFlag, hostKeys, changePin          bool
		listsupported                           bool
		printPubkey                             string
		parentHandle, wrap, wrapWith            string
		hierarchy                               string
	)

	flag.BoolVar(&askOwnerPassword, "o", false, "ask for the owner password")
	flag.BoolVar(&askOwnerPassword, "owner-password", false, "ask for the owner password")
	flag.StringVar(&comment, "C", defaultComment(), "provide a comment, default to user@host")
	flag.StringVar(&outputFile, "f", "", "output keyfile")
	flag.StringVar(&keyPin, "N", "", "new passphrase for the key")
	flag.StringVar(&keyType, "t", "ecdsa", "key to create")
	flag.IntVar(&bits, "b", 0, "number of bits")
	flag.StringVar(&importKey, "I", "", "import key")
	flag.StringVar(&importKey, "import", "", "import key")
	flag.BoolVar(&changePin, "p", false, "change passphrase")
	flag.StringVar(&passphrase, "P", "", "old passphrase")
	flag.BoolVar(&swtpmFlag, "swtpm", false, "use swtpm instead of actual tpm")
	flag.BoolVar(&hostKeys, "A", false, "generate host keys")
	flag.BoolVar(&listsupported, "supported", false, "list tpm caps")
	flag.StringVar(&printPubkey, "print-pubkey", "", "print tpm pubkey")
	flag.StringVar(&wrap, "wrap", "", "wrap key")
	flag.StringVar(&wrapWith, "wrap-with", "", "wrap with key")
	flag.StringVar(&parentHandle, "parent-handle", "owner", "parent handle for the key")
	flag.StringVar(&hierarchy, "hierarchy", "", "hierarchy for the created key")

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

	if listsupported {
		fmt.Printf("ecdsa bit lengths:")
		for _, alg := range supportedECCBitsizes {
			fmt.Printf(" %d", alg)
		}
		fmt.Println("\nrsa bit lengths: 2048")
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
		doHostKeys(tpm, outputFile, ownerPassword, hierarchy)
		os.Exit(0)
	}

	var filename string
	var privatekeyFilename string
	var pubkeyFilename string

	// TODO: Support custom handles
	var keyParentHandle tpm2.TPMHandle
	if parentHandle != "" {
		keyParentHandle, err = utils.GetParentHandle(parentHandle)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Create ~/.ssh if it doesn't exist
	if !utils.FileExists(utils.SSHDir()) {
		if err := os.Mkdir(utils.SSHDir(), 0o700); err != nil {
			log.Fatalf("Could not create directory %s", utils.SSHDir())
			os.Exit(1)
		}
	}

	// Wrapping of keyfile for import
	if wrap != "" {
		if wrapWith == "" {
			log.Fatal("--wrap needs --wrap-with")
		}

		if outputFile == "" {
			log.Fatal("Specify output filename with --output/-o")
		}

		doWrapWith(supportedECCBitsizes, wrap, wrapWith, keyParentHandle, comment, outputFile)
		os.Exit(0)
	}

	switch keyType {
	case "ecdsa":
		filename = "id_ecdsa"
		if !slices.Contains(supportedECCBitsizes, bits) {
			log.Fatalf("invalid ecdsa key length: TPM does not support %v bits", bits)
		}
	case "rsa":
		filename = "id_rsa"
	}

	if outputFile != "" {
		filename = outputFile
	} else {
		filename = path.Join(utils.SSHDir(), filename)
	}

	if changePin {
		if err := doChangePin(tpm, []byte(passphrase), []byte(keyPin), ownerPassword, filename, outputFile); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	// If we don't need to write a public key
	var writePubKey bool

	var k *key.SSHTPMKey

	if importKey != "" {
		pem, err := os.ReadFile(importKey)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := keyfile.Decode(pem); !errors.Is(err, keyfile.ErrNotTPMKey) {
			fmt.Println("Importing a wrapped public/private key pair.")
			k, err = doImportWrappedKey(tpm, ownerPassword, pem)
			if err != nil {
				log.Fatal(err)
			}
			writePubKey = true
		} else {
			// Import a ssh key if it's not a TPM key
			fmt.Println("Sealing an existing public/private key pair.")
			k, err = doImportKey(tpm, keyParentHandle, ownerPassword, keyPin, pem, importKey)
			if err != nil {
				log.Fatal(err)
			}
			writePubKey = false
		}
	} else {
		// Else create a normal key
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
		k, err = doCreateSSHKey(tpm, ownerPassword, keyPin, keyParentHandle, keyType, comment, bits)
		if err != nil {
			log.Fatal(err)
		}
		writePubKey = true
	}

	privatekeyFilename = filename + ".tpm"
	if err := checkFile(privatekeyFilename); err != nil {
		log.Fatal(err)
	}

	pubkeyFilename = filename + ".pub"
	if err := checkFile(pubkeyFilename); err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(privatekeyFilename, k.Bytes(), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Your identification has been saved in %s\n", privatekeyFilename)
	if writePubKey {
		if err := os.WriteFile(pubkeyFilename, k.AuthorizedKey(), 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Your public key has been saved in %s\n", pubkeyFilename)
	}
	fmt.Printf("The key fingerprint is:\n")
	fmt.Println(k.Fingerprint())
	fmt.Println("The key's randomart image is the color of television, tuned to a dead channel.")
}
