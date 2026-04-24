package agent

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxPeerChain = 4

// peerChain describes the process at the other end of c and a few of its
// ancestors, e.g. "ssh (1234) ← git ← zsh ← kitty". Best effort; returns ""
// if SO_PEERCRED or /proc are unavailable.
func peerChain(c *net.UnixConn) string {
	rc, err := c.SyscallConn()
	if err != nil {
		return ""
	}
	var ucred *unix.Ucred
	if cerr := rc.Control(func(fd uintptr) {
		ucred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || err != nil {
		return ""
	}

	var parts []string
	for i, pid := 0, int(ucred.Pid); i < maxPeerChain && pid > 1; i++ {
		name, ppid := procStatus(pid)
		if name == "" {
			break
		}
		if i == 0 {
			name = fmt.Sprintf("%s (%d)", name, pid)
		}
		parts = append(parts, name)
		pid = ppid
	}
	return strings.Join(parts, " ← ")
}

// procStatus returns Name and PPid from /proc/<pid>/status.
func procStatus(pid int) (name string, ppid int) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Name:"); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			ppid, _ = strconv.Atoi(strings.TrimSpace(v))
			return
		}
	}
	return
}
