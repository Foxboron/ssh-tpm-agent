package askpass

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Most of this is copied from OpenSSH readpassphrase.

// State for the ReadPassphrase function
type ReadPassFlags int

const (
	_                 ReadPassFlags = iota
	RP_ECHO                         /* echo stuff or something 8 */
	RP_ALLOW_STDIN                  /* Allow stdin and not askpass */
	RP_ALLOW_EOF                    /* not used */
	RP_USE_ASKPASS                  /* Use SSH_ASKPASS */
	RP_ASK_PERMISSION               /* Ask for permission, yes/no prompt */
	RP_NEWLINE                      /* Print newline after answer. */
	RPP_ECHO_OFF                    /* Turn off echo (default). */
	RPP_ECHO_ON                     /* Leave echo on. */
	RPP_REQUIRE_TTY                 /* Fail if there is no tty. */
	RPP_FORCELOWER                  /* Force input to lower case. */
	RPP_FORCEUPPER                  /* Force input to upper case. */
	RPP_SEVENBIT                    /* Strip the high bit from input. */
	RPP_STDIN                       /* Read from stdin, not /dev/tty */
)

// Default ASKPASS programs
var SSH_ASKPASS_DEFAULTS = []string{
	"/usr/lib/ssh/x11-ssh-askpass",
	"/usr/lib/ssh/gnome-ssh-askpass3",
	"/usr/lib/ssh/gnome-ssh-askpass",
}

func findAskPass() string {
	for _, s := range SSH_ASKPASS_DEFAULTS {
		if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) {
			continue
		}
		return s
	}
	return ""
}

func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

func ReadPassphrase(prompt string, flags ReadPassFlags) []byte {
	var allow_askpass bool
	var use_askpass bool
	var askpass_hint string

	if _, ok := os.LookupEnv("DISPLAY"); ok {
		allow_askpass = true
	} else if _, ok2 := os.LookupEnv("WAYLAND_DISPLAY"); ok2 {
		allow_askpass = true
	}

	if s, ok := os.LookupEnv("SSH_ASKPASS_REQUIRE"); ok {
		switch s {
		case "force":
			use_askpass = true
			allow_askpass = true
		case "prefer":
			use_askpass = allow_askpass
		case "never":
			allow_askpass = false
		}
	}

	if use_askpass {
		slog.Debug("requested to askpass")
	} else if (flags & RP_USE_ASKPASS) != 0 {
		use_askpass = true
	} else if (flags & RP_ALLOW_STDIN) != 0 {
		if !isTerminal(os.Stdout.Fd()) {
			slog.Debug("stdin is not a tty")
			use_askpass = true
		}
	}

	if use_askpass && allow_askpass {
		if (flags & RP_ASK_PERMISSION) != 0 {
			askpass_hint = "confirm"
		}
		return SshAskPass(prompt, askpass_hint)
	}

	// If we want to echo stuff, we read directly from stdin
	// using bufio.NewReader.
	if (flags & RPP_ECHO_ON) != 0 {
		fmt.Printf("%s", prompt)
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return []byte("")
		}
		return []byte(strings.TrimSpace(input))
	}
	// Then we are defaulting to TTY prompt
	fmt.Printf("%s: ", prompt)
	pin, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return []byte{}
	}
	if (flags & RP_NEWLINE) != 0 {
		fmt.Println("")
	}
	return pin
}

func SshAskPass(prompt, hint string) []byte {
	var askpass string
	if s, ok := os.LookupEnv("SSH_ASKPASS_ENV"); ok {
		askpass = s
	} else if s, _ := exec.LookPath("ssh-askpass"); s != "" {
		askpass = s
	} else if s := findAskPass(); s != "" {
		askpass = findAskPass()
	}

	if hint != "" {
		os.Setenv("SSH_ASKPASS_PROMPT", hint)
	}
	out, err := exec.Command(askpass).Output()
	switch hint {
	case "confirm":
		// TODO: Ugly and needs a rework
		var exerr *exec.ExitError
		if errors.As(err, &exerr) {
			if exerr.ExitCode() != 0 {
				return []byte("no")
			}
		} else {
			return []byte("yes")
		}
	}

	if err != nil {
		return []byte{}
	}
	return out
}

// AskPremission runs SSH_ASKPASS in with SSH_ASKPASS_PROMPT=confirm set as env
// it will expect exit code 0 or !0 and return 'yes' and 'no' respectively.
func AskPermission() bool {
	a := ReadPassphrase("Confirm touch", RP_USE_ASKPASS|RP_ASK_PERMISSION)
	if bytes.Equal(a, []byte("yes")) {
		return true
	} else if bytes.Equal(a, []byte("no")) {
		return false
	}
	return false
}
