module github.com/foxboron/ssh-tpm-agent

go 1.22.4

toolchain go1.22.5

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240620184055-b891af1cbc88
	github.com/foxboron/ssh-tpm-ca-authority v0.0.0-20240714160518-efbdf2e250b6
	github.com/foxboron/swtpm_test v0.0.0-20230726224112-46aaafdf7006
	github.com/google/go-tpm v0.9.2-0.20240625170440-991b038b62b6
	golang.org/x/crypto v0.25.0
	golang.org/x/exp v0.0.0-20240222234643-814bf88cf225
	golang.org/x/sys v0.22.0
	golang.org/x/term v0.22.0
)

require github.com/google/go-tpm-tools v0.4.4 // indirect
