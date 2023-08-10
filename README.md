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
* Create sealed ssh keys on the TPM.
* PIN support, dictionary attacks protection from the TPM allows users to use low entropy PINs instead of passphrases.
* TPM session encryption.
* Proxy support towards other `ssh-agent` servers for fallbacks.

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

`go install github.com/foxboron/ssh-tpm-agent/cmd/...@latest`

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

### Import existing key

Usefull if you want to back up the key to a remote secure storage whil using the key day-to-day from the TPM.

```bash
// Create a key, or use an existing one
$ ssh-keygen -t ecdsa -f id_ecdsa
Generating public/private ecdsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_ecdsa
Your public key has been saved in id_ecdsa.pub
The key fingerprint is:
SHA256:bDn2EpX6XRX5ADXQSuTq+uUyia/eV3Z6MW+UtxjnXvU fox@framework
The key's randomart image is:
+---[ECDSA 256]---+
|           .+=o..|
|           o. oo.|
|          o... .o|
|       . + ..  ..|
|        S .   . o|
|       o * . oo=*|
|        ..+.oo=+E|
|        .++o...o=|
|       .++++. .+ |
+----[SHA256]-----+

// Import the key
$ ssh-tpm-keygen --import id_ecdsa
Sealing an existing public/private ecdsa key pair.
Enter pin (empty for no pin):
Confirm pin:
Your identification has been saved in id_ecdsa.tpm
The key fingerprint is:
SHA256:bDn2EpX6XRX5ADXQSuTq+uUyia/eV3Z6MW+UtxjnXvU
The key's randomart image is the color of television, tuned to a dead channel.
```

### Install user service

Socket activated services allows you to start `ssh-tpm-agent` when it's needed by your system.

```bash
# Using the socket
$ ssh-tpm-agent --install-user-units
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.socket
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.service
Enable with: systemctl --user enable --now ssh-tpm-agent.socket

$ systemctl --user enable --now ssh-tpm-agent.socket

$ export SSH_AUTH_SOCK="/run/user/$(id -u)/ssh-tpm-agent.sock" ssh git@github.com
```


### Proxy support

```
// Start the usual ssh-agent
$ eval $(ssh-agent)

// Create a strong RSA key
$ ssh-keygen -t rsa -b 4096 -f id_rsa -C ssh-agent
...
The key fingerprint is:
SHA256:zLSeyU/6NKHGEvyZLA866S1jGqwdwdAxRFff8Z2N1i0 ssh-agent

$ ssh-add id_rsa
Identity added: id_rsa (ssh-agent)

// Print looonnggg key
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent


// Create key on the TPM
$ ssh-tpm-keygen -C ssh-tpm-agent
Generating a sealed public/private ecdsa key pair.
Enter file in which to save the key (/home/fox/.ssh/id_ecdsa):
Enter pin (empty for no pin):
Confirm pin:
Your identification has been saved in /home/fox/.ssh/id_ecdsa.tpm
Your public key has been saved in /home/fox/.ssh/id_ecdsa.pub
The key fingerprint is:
SHA256:PoQyuzOpEBLqT+xtP0dnvyBVL6UQTiQeCWN/EXIxPOo
The key's randomart image is the color of television, tuned to a dead channel.

// Start ssh-tpm-agent with a proxy socket
$ ssh-tpm-agent -A "${SSH_AUTH_SOCK}" &

$ export SSH_AUTH_SOCK="/run/user/$(id -u)/ssh-tpm-agent.sock"

// ssh-tpm-agent is proxying the keys from ssh-agent
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo[...]q4whro= ssh-tpm-agent
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
    IdentityAgent /run/user/1000/ssh-tpm-agent.sock
    IdentityFile ~/.ssh/id_ecdsa.pub
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or http://opensource.org/licenses/MIT
