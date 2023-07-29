SSH agent for TPM
=================

`ssh-tpm-agent` is a ssh-agent compatible agent that allows keys to be created
by the Trusted Platform Module (TPM) for authentication towards ssh servers.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in `.tpm` suffixed files. They are bound to the hardware they
where produced on and can't be transferred to other machines.

This allows one to utilize a native client instead of having to side load
existing PKCS11 libraries into the ssh-agent and/or ssh client.

# Features

* A working `ssh-agent`.
* Keys created on the TPM, sealed outside of it.
* PIN support.
* TPM session encryption.

# Experimental

The key format and technical details might change between iterations.  Consider
this agent experimental.

Instead of utilizing the TPM directly, you can use `--swtpm` or `export
SSH_TPM_AGENT_SWTPM=1` to create a identity backed by
[swtpm](https://github.com/stefanberger/swtpm) which will be stored under
`/var/tmp/ssh-tpm-agent`.

Note that `swtpm` provides no security properties and should only be used for
testing.

## Installation

The simplest way of installing this plugin is by running the follow go command.

`go install github.com/Foxboron/ssh-tpm-agent/cmd/...@latest`

Alternatively download the [pre-built binaries](https://github.com/Foxboron/ssh-tpm-agent/releases).

# Usage

```bash
# Create key
$ ssh-tpm-keygen
Generating a sealed public/private ecdsa key pair.
Enter file in which to save the key (/home/fox/.ssh/id_ecdsa):
Enter pin (empty for no pin):
Enter same pin again:
Your identification has been saved in /home/fox/.ssh/id_ecdsa.tpm
Your public key has been saved in /home/fox/.ssh/id_ecdsa.pub
The key fingerprint is:
SHA256:NCMJJ2La+q5tGcngQUQvEOJP3gPH8bMP98wJOEMV564
The key's randomart image is the color of television, tuned to a dead channel.

$ cat /home/fox/.ssh/id_ecdsa.pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOTOsMXyjTc1wiQSKhRiNhKFsHJNLzLk2r4foXPLQYKR0tuXIBMTQuMmc7OiTgNMvIjMrcb9adgGdT3s+GkNi1g=

# Using the socket
$ ssh-tpm-agent -l /var/tmp/tpm.sock

$ export SSH_AUTH_SOCK="/var/tmp/tpm.sock" ssh git@github.com
```

# ssh-config

It is possible to use the public keys created by `ssh-tpm-keygen` inside ssh
configurations.

The below example uses `ssh-tpm-agent` and also passes the public key to ensure
not all identities are leaked from the agent.

```
Host example.com
    IdentityAgent $SSH_AUTH_SOCK

Host *
    IdentityAgent /var/tmp/tpm.sock
    IdentityFile ~/.ssh/id_ecdsa.pub
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT
