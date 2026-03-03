# User Setup

This guide is for a user who wants to obtain a CA-signed SSH certificate for their own key. A signed user certificate lets you log in to any server that trusts the CA without needing your public key copied there in advance.

**Audience:** end user on a workstation or laptop.

**Prerequisites:**
- The CA is already running. See [CA Server Setup](setup-ca.md).
- You have an SSH key pair. If not, generate one: `ssh-keygen -t ed25519`.
- You have a valid account on the CA server (the CA operator must have added you to the user list).
- `bash`, `ssh`, and `ssh-keygen` are available (standard on any Linux system). `getopt` from `util-linux` is also required and present by default on all major distributions.

There are two ways to install the client script: from a pre-built Debian package or manually from the repository.

## Table of Contents

1. [Trust the CA](#1-trust-the-ca)
- [Option A: Install from the Debian package](#option-a-install-from-the-debian-package)
- [Option B: Install manually from the repository](#option-b-install-manually-from-the-repository)
2. [Request a user certificate](#2-request-a-user-certificate)
3. [Configure the SSH client](#3-configure-the-ssh-client)

---

## 1. Trust the CA

Before your SSH client will accept certificates signed by this CA, you must tell it to trust the CA's public key. Add the following line to `/etc/ssh/ssh_known_hosts` (system-wide) or `~/.ssh/known_hosts` (per user):

```
@cert-authority * <contents of /etc/ssh_ca_server/ca_key.pub>
```

Ask your CA operator for the CA public key, or copy it directly from the server:

```bash
# On the CA server
cat /etc/ssh_ca_server/ca_key.pub

# On your workstation — append to your personal known_hosts
echo "@cert-authority * $(cat ca_key.pub)" >> ~/.ssh/known_hosts

# Or system-wide
echo "@cert-authority * $(cat ca_key.pub)" | sudo tee -a /etc/ssh/ssh_known_hosts
```

> If the CA was installed from source, the key may be at a different path (e.g. `/etc/ssh_ca/ca_key.pub`). Ask your CA operator to confirm.

---

## Option A: Install from the Debian package

Pre-built packages are published as assets on every [GitHub Release](https://github.com/your-org/ssh_acme_server/releases). The client package works on any Debian or Ubuntu system regardless of architecture.

Go to the [latest release](https://github.com/your-org/ssh_acme_server/releases/latest) and download `ssh-ca-client_<version>_all.deb`. Then install it:

```bash
sudo dpkg -i ssh-ca-client_<version>_all.deb
sudo apt-get install -f   # resolves the openssh-client dependency if needed
```

The package installs:

| Binary | Path |
|---|---|
| `ssh-ca-sign-user-key` | `/usr/bin/ssh-ca-sign-user-key` |
| `ssh-ca-sign-host-key` | `/usr/sbin/ssh-ca-sign-host-key` |

---

## Option B: Install manually from the repository

Copy the script from the `clients/` directory of the repository to a directory on `$PATH`:

```bash
sudo cp clients/ssh-ca-sign-user-key.sh /usr/local/bin/ssh-ca-sign-user-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-user-key
```

---

## 2. Request a user certificate

Run the script on your workstation. It authenticates with your password (PAM), sends your public key to the CA, and writes the signed certificate to disk. You will be prompted for your password interactively.

```bash
ssh-ca-sign-user-key -s ca-server.example.com
```

This signs `~/.ssh/id_ed25519.pub` and writes the certificate to `~/.ssh/id_ed25519-cert.pub`.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--user <NAME>` | `-u` | `$USER` | Username for authentication |
| `--key <PATH>` | `-k` | `~/.ssh/id_ed25519.pub` | Public key to sign |
| `--output <PATH>` | `-o` | `<key>-cert.pub` | Output certificate path |
| `--known-hosts <PATH>` | | system default | Custom known_hosts file for the CA |
| `--no-host-check` | | off | Disable CA host key verification |
| `--retry <N>` | | `0` | Number of retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Enable verbose output |

### Examples

```bash
# Sign the default key; prompts for password
ssh-ca-sign-user-key -s ca-server.example.com

# Sign a specific key as a named user
ssh-ca-sign-user-key -s ca-server.example.com -u alice -k ~/.ssh/id_ed25519.pub

# Custom port, explicit output path, verbose logging
ssh-ca-sign-user-key -s ca-server.example.com -p 2222 \
    -o ~/.ssh/id_ed25519-cert.pub -v

# Retry up to 3 times with a 10-second delay between attempts
ssh-ca-sign-user-key -s ca-server.example.com --retry 3 --retry-delay 10
```

The script prints the certificate details via `ssh-keygen -L` on success.

### Manual alternative

If the script is not available, the same operation can be performed with a raw `ssh` command:

```bash
ssh -T -p 2222 alice@ca-server.example.com \
    < ~/.ssh/id_ed25519.pub \
    > ~/.ssh/id_ed25519-cert.pub
```

---

## 3. Configure the SSH client

Add the following to `~/.ssh/config` so the certificate is presented automatically when you connect to any host:

```
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile    ~/.ssh/id_ed25519
```

Your certificate has a limited validity period (set by the CA operator). Re-run the script before it expires to renew it.

---

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.