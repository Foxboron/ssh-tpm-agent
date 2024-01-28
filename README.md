SSH agent for TPM
=================

`ssh-tpm-agent` is a ssh-agent compatible agent that allows keys to be created
by the Trusted Platform Module (TPM) for authentication towards ssh servers.

TPM sealed keys are private keys created inside the Trusted Platform Module
(TPM) and sealed in `.tpm` suffixed files. They are bound to the hardware they
are produced on and can't be transferred to other machines.

This allows you to utilize a native client instead of having to side load
existing PKCS11 libraries into the ssh-agent and/or ssh client.

# Features

* A working `ssh-agent`.
* Create sealed ssh keys on the TPM.
* PIN support, dictionary attack protection from the TPM allows you to use low entropy PINs instead of passphrases.
* TPM session encryption.
* Proxy support towards other `ssh-agent` servers for fallbacks.

# SWTPM support

Instead of utilizing the TPM directly, you can use `--swtpm` or `export
SSH_TPM_AGENT_SWTPM=1` to create an identity backed by
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

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh git@github.com
```

**Note:** For `ssh-tpm-agent` you can specify the TPM owner password using the command line flags `-o` or `--owner-password`, which are preferred. Alternatively, you can use the environment variable `SSH_TPM_AGENT_OWNER_PASSWORD`.

### Import existing key

Useful if you want to back up the key to a remote secure storage while using the key day-to-day from the TPM.

```bash
# Create a key, or use an existing one
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

# Import the key
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

Socket activated services allow you to start `ssh-tpm-agent` when it's needed by your system.

```bash
# Using the socket
$ ssh-tpm-agent --install-user-units
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.socket
Installed /home/fox/.config/systemd/user/ssh-tpm-agent.service
Enable with: systemctl --user enable --now ssh-tpm-agent.socket

$ systemctl --user enable --now ssh-tpm-agent.socket

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh git@github.com
```


### Proxy support

```bash
# Start the usual ssh-agent
$ eval $(ssh-agent)

# Create a strong RSA key
$ ssh-keygen -t rsa -b 4096 -f id_rsa -C ssh-agent
...
The key fingerprint is:
SHA256:zLSeyU/6NKHGEvyZLA866S1jGqwdwdAxRFff8Z2N1i0 ssh-agent

$ ssh-add id_rsa
Identity added: id_rsa (ssh-agent)

# Print looonnggg key
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent

# Create key on the TPM
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

# Start ssh-tpm-agent with a proxy socket
$ ssh-tpm-agent -A "${SSH_AUTH_SOCK}" &

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

# ssh-tpm-agent is proxying the keys from ssh-agent
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc[...]8TWynQ== ssh-agent
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNo[...]q4whro= ssh-tpm-agent
```

### ssh-tpm-add

```bash
$ ssh-tpm-agent --no-load &
2023/08/12 13:40:50 Listening on /run/user/1000/ssh-tpm-agent.sock

$ export SSH_AUTH_SOCK="$(ssh-tpm-agent --print-socket)"

$ ssh-add -L
The agent has no identities.

$ ssh-tpm-add $HOME/.ssh/id_ecdsa.tpm
Identity added: /home/user/.ssh/id_ecdsa.tpm

$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJCxqisGa9IUNh4Ik3kwihrDouxP7S5Oun2hnzTvFwktszaibJruKLJMxHqVYnNwKD9DegCNwUN1qXCI/UOwaSY= test
```

### ssh-tpm-hostkey

`ssh-tpm-agent` also supports storing host keys inside the TPM.

```bash
$ sudo ssh-tpm-keygen -A
2023/09/03 17:03:08 INFO Generating new ECDSA host key
2023/09/03 17:03:08 INFO Wrote /etc/ssh/ssh_tpm_host_ecdsa_key.tpm
2023/09/03 17:03:08 INFO Generating new RSA host key
2023/09/03 17:03:15 INFO Wrote /etc/ssh/ssh_tpm_host_rsa_key.tpm

$ sudo ssh-tpm-hostkeys --install-system-units
Installed /usr/lib/systemd/system/ssh-tpm-agent.service
Installed /usr/lib/systemd/system/ssh-tpm-agent.socket
Installed /usr/lib/systemd/system/ssh-tpm-genkeys.service
Enable with: systemctl enable --now ssh-tpm-agent.socket

$ sudo ssh-tpm-hostkeys --install-sshd-config
Installed /etc/ssh/sshd_config.d/10-ssh-tpm-agent.conf
Restart sshd: systemd restart sshd

$ systemctl enable --now ssh-tpm-agent.socket
$ systemd restart sshd

$ sudo ssh-tpm-hostkeys
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCLDH2xMDIGb26Q3Fa/kZDuPvzLzfAH6CkNs0wlaY2AaiZT2qJkWI05lMDm+mf+wmDhhgQlkJAHmyqgzYNwqWY0= root@framework
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAoMPsv5tEpTDFw34ltkF45dTHAPl4aLu6HigBkNnIzsuWqJxhjN6JK3vaV3eXBzy8/UJxo/R0Ml9/DRzFK8cccdIRT1KQtg8xIikRReZ0usdeqTC+wLpW/KQqgBLZ1PphRINxABWReqlnbtPVBfj6wKlCVNLEuTfzi1oAMj3KXOBDcTTB2UBLcwvTFg6YnbTjrpxY83Y+3QIZNPwYqd7r6k+e/ncUl4zgCvvxhoojGxEM3pjQIaZ0Him0yT6OGmCGFa7XIRKxwBSv9HtyHf5psgI+X5A2NV2JW2xeLhV2K1+UXmKW4aXjBWKSO08lPSWZ6/5jQTGN1Jg3fLQKSe7f root@framework

$ ssh-keyscan -t ecdsa localhost
# localhost:22 SSH-2.0-OpenSSH_9.4
localhost ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCLDH2xMDIGb26Q3Fa/kZDuPvzLzfAH6CkNs0wlaY2AaiZT2qJkWI05lMDm+mf+wmDhhgQlkJAHmyqgzYNwqWY0=
```

Note: sshd seems to be a bit flakey when it decides to sign with `SHA256` or `SHA512`, so your mileage might vary. Only `SHA256` is supported by `ssh-tpm-agent`.

# ssh-config

It is possible to use the public keys created by `ssh-tpm-keygen` inside ssh
configurations.

The below example uses `ssh-tpm-agent` and also passes the public key to ensure
not all identities are leaked from the agent.

```sshconfig
Host example.com
    IdentityAgent $SSH_AUTH_SOCK

Host *
    IdentityAgent /run/user/1000/ssh-tpm-agent.sock
    IdentityFile ~/.ssh/id_ecdsa.pub
```

## License

Licensed under the MIT license. See [LICENSE](LICENSE) or https://opensource.org/licenses/MIT
