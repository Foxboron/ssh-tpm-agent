package utils

import (
	"errors"
	"os"
	"path"

	swtpm "github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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

var (
	swtpmPath = "/var/tmp/ssh-tpm-agent"
)

// Smaller wrapper for getting the correct TPM instance
func GetTPM(f bool) (transport.TPMCloser, error) {
	var tpm transport.TPMCloser
	var err error
	if f || os.Getenv("SSH_TPM_AGENT_SWTPM") != "" {
		if _, err := os.Stat(swtpmPath); errors.Is(err, os.ErrNotExist) {
			os.MkdirTemp(path.Dir(swtpmPath), path.Base(swtpmPath))
		}
		tpm, err = swtpm.OpenSwtpm(swtpmPath)
	} else {
		tpm, err = transport.OpenTPM()
	}
	if err != nil {
		return nil, err
	}
	return tpm, nil
}
