SSH agent for TPM
=================

`tpm-ssh-agent` is a ssh-agent that allows keys to be created by the Trusted
Platform Module (TPM), sealed outside of it, for authentication towards ssh
servers.

This allows one to utilize a native client instead of having to side load
existing PKCS11 libraries into the ssh-agent and/or ssh client.

# Features

* A working `ssh-agent`.
* Keys created on the TPM, sealed outside of it.
* PIN support.
* TPM session encryption.

# Experimental

The identity format and technical details might change between iterations.
Consider this plugin experimental.

Instead of utilizing the TPM directly, you can use `--swtpm` or `export
TPM_SSH_AGENT_SWTPM=1` to create a identity backed by
[swtpm](https://github.com/stefanberger/swtpm) which will be stored under
`/var/tmp/tpm-agent-ssh`.

Note that `swtpm` provides no security properties and should only be used for
testing.

## Installation

The simplest way of installing this plugin is by running the follow go command.

`go install github.com/Foxboron/tpm-ssh-agent@latest`

Alternatively download the [pre-built binaries](https://github.com/foxboron/tpm-ssh-plugin/releases).

# Usage

```bash
# Create key
$ tpm-ssh-agent --setup
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9BTy8bdarJoivDAQv0rVdJDvapvaNcFnCzqq8M5MFqQzxSdFEJCMAODngCFnuOnVRt1CCuEvnrfZQNj2XkHhU=

# Using the socket
$ tpm-ssh-agent -l /var/tmp/tpm.sock

$ export SSH_AUTH_SOCK="/var/tmp/tpm.sock" ssh git@github.com
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT
