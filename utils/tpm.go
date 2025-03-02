package utils

import (
	"errors"
	"io"
	"os"
	"path"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"

	sim "github.com/google/go-tpm-tools/simulator"
)

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func FlushHandle(tpm transport.TPM, h handle) {
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}

var swtpmPath = "/var/tmp/ssh-tpm-agent"

// TPM represents a connection to a TPM simulator.
type TPMCloser struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPMCloser) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPMCloser) Close() error {
	return t.transport.Close()
}

var (
	once sync.Once
	s    transport.TPMCloser
)

func GetFixedSim() (transport.TPMCloser, error) {
	var ss *sim.Simulator
	var err error
	once.Do(func() {
		ss, err = sim.GetWithFixedSeedInsecure(123456)
		s = &TPMCloser{ss}
	})
	return s, err
}

var cache struct {
	sync.Once
	tpm transport.TPMCloser
	err error
}

// Smaller wrapper for getting the correct TPM instance
func TPM(f bool) (transport.TPMCloser, error) {
	cache.Do(func() {
		if f || os.Getenv("SSH_TPM_AGENT_SWTPM") != "" {
			if _, err := os.Stat(swtpmPath); errors.Is(err, os.ErrNotExist) {
				os.MkdirTemp(path.Dir(swtpmPath), path.Base(swtpmPath))
			}
			cache.tpm, cache.err = simulator.OpenSimulator()
		} else if f || os.Getenv("_SSH_TPM_AGENT_SIMULATOR") != "" {
			// Implements an insecure fixed thing
			cache.tpm, cache.err = GetFixedSim()
		} else {
			cache.tpm, cache.err = transport.OpenTPM("/dev/tpmrm0")
		}
	})
	return cache.tpm, cache.err
}

func EnvSocketPath(socketPath string) string {
	// Find a default socket name from ssh-tpm-agent.service
	if val, ok := os.LookupEnv("SSH_TPM_AUTH_SOCK"); ok && socketPath == "" {
		return val
	}

	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = "/var/tmp"
	}
	return path.Join(dir, "ssh-tpm-agent.sock")
}
