package script_tests

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/go-tpm-keyfiles/pkix"
	"github.com/foxboron/ssh-tpm-agent/utils"
	"github.com/google/go-tpm/tpm2"
	"github.com/rogpeppe/go-internal/testscript"
)

func ScriptsWithPath(t *testing.T, path string) {
	tmp := t.TempDir()
	fmt.Println("built")
	c := exec.Command("go", "build", "-buildmode=pie", "-o", tmp, "../cmd/...")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}
	testscript.Run(t, testscript.Params{
		Deadline: time.Now().Add(5 * time.Second),
		Setup: func(e *testscript.Env) error {
			e.Setenv("PATH", tmp+string(filepath.ListSeparator)+e.Getenv("PATH"))
			e.Vars = append(e.Vars, "_SSH_TPM_AGENT_SIMULATOR=1")
			e.Vars = append(e.Vars, fmt.Sprintf("SSH_AUTH_SOCK=%s/agent.sock", e.WorkDir))
			e.Vars = append(e.Vars, fmt.Sprintf("SSH_TPM_AUTH_SOCK=%s/agent.sock", e.WorkDir))
			e.Vars = append(e.Vars, fmt.Sprintf("HOME=%s", e.WorkDir))
			return nil
		},
		Dir: path,
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// Create an EK certificate from our fixed seed simulator
			"getekcert": func(ts *testscript.TestScript, neg bool, args []string) {
				tpm, err := utils.GetFixedSim()
				if err != nil {
					t.Fatal(err)
				}
				defer tpm.Close()
				rsp, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.AuthHandle{
						Handle: tpm2.TPMRHOwner,
						Auth:   tpm2.PasswordAuth([]byte(nil)),
					},
					InSensitive: tpm2.TPM2BSensitiveCreate{
						Sensitive: &tpm2.TPMSSensitiveCreate{
							UserAuth: tpm2.TPM2BAuth{
								Buffer: []byte(nil),
							},
						},
					},
					InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
				}.Execute(tpm)
				if err != nil {
					log.Fatalf("failed creating primary key: %v", err)
				}
				keyfile.FlushHandle(tpm, rsp.ObjectHandle)
				srkPublic, err := rsp.OutPublic.Contents()
				if err != nil {
					log.Fatalf("failed getting srk public content: %v", err)
				}
				b, err := pkix.FromTPMPublic(srkPublic)
				if err != nil {
					log.Fatal(err)
				}
				if err := os.WriteFile(ts.MkAbs("srk.pem"),
					pem.EncodeToMemory(&pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: b,
					}), 0664); err != nil {
					log.Fatal(err)
				}
			},
		},
	})
}

func TestAgent(t *testing.T) {
	ScriptsWithPath(t, "ssh-tpm-agent/testdata/script")
}

func TestKeygen(t *testing.T) {
	ScriptsWithPath(t, "ssh-tpm-keygen/testdata/script")
}

// func TestAdd(t *testing.T) {
// 	ScriptsWithPath(t, "ssh-tpm-add/testdata/script")
// }

// func TestHostkeys(t *testing.T) {
// 	ScriptsWithPath(t, "ssh-tpm-hostkeys/testdata/script")
// }
