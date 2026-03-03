# Host Setup

This guide is for the administrator of a server that should receive a CA-signed SSH host certificate. A signed host certificate lets SSH clients verify your server's identity without a manual `known_hosts` entry.

**Audience:** system administrator managing a host that will be enrolled with the CA.

**Prerequisites:**
- The CA is already running. See [CA Server Setup](setup-ca.md).
- Your host's public key has been added to the CA's host inventory by the CA operator (see the *Host inventory entry* section of [CA Server Setup](setup-ca.md)).
- `bash`, `ssh`, and `ssh-keygen` are available on the host (standard on any Linux system). `getopt` from `util-linux` is also required and present by default on all major distributions.

There are two ways to install the client script: from a pre-built Debian package or manually from the repository.

## Table of Contents

- [Option A: Install from the Debian package](#option-a-install-from-the-debian-package)
- [Option B: Install manually from the repository](#option-b-install-manually-from-the-repository)
- [Request a host certificate](#request-a-host-certificate)
- [Configure sshd](#configure-sshd)
- [Automate renewal with a systemd timer](#automate-renewal-with-a-systemd-timer)

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
sudo cp clients/ssh-ca-sign-host-key.sh /usr/local/bin/ssh-ca-sign-host-key
sudo chmod +x /usr/local/bin/ssh-ca-sign-host-key
```

---

## Request a host certificate

Run the script as root (required to read the host private key). The script authenticates to the CA using the host's own private key and writes the signed certificate to disk.

```bash
sudo ssh-ca-sign-host-key -s ca-server.example.com
```

This signs `/etc/ssh/ssh_host_ed25519_key` and writes the certificate to `/etc/ssh/ssh_host_ed25519_key-cert.pub`.

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <HOST>` | `-s` | *(required)* | CA server address |
| `--port <PORT>` | `-p` | `2222` | CA server SSH port |
| `--identity <PATH>` | `-i` | `/etc/ssh/ssh_host_ed25519_key` | Host private key |
| `--hostname <NAME>` | `-n` | `$(hostname)` | Hostname to authenticate as |
| `--output <PATH>` | `-o` | `<identity>-cert.pub` | Output certificate path |
| `--known-hosts <PATH>` | | system default | Custom known_hosts file for the CA |
| `--no-host-check` | | off | Disable CA host key verification |
| `--reload` | | off | Reload sshd after signing |
| `--retry <N>` | | `0` | Number of retry attempts |
| `--retry-delay <SEC>` | | `5` | Seconds between retries |
| `--verbose` | `-v` | off | Enable verbose output |

### Examples

```bash
# Sign the default host key
sudo ssh-ca-sign-host-key -s ca-server.example.com

# Sign a specific key, reload sshd automatically when done
sudo ssh-ca-sign-host-key -s ca-server.example.com \
    -i /etc/ssh/ssh_host_ed25519_key --reload

# Custom port, explicit hostname, retry on failure
sudo ssh-ca-sign-host-key -s ca-server.example.com -p 2222 \
    -n webserver --retry 3

# Use a dedicated known_hosts file for the CA server
sudo ssh-ca-sign-host-key -s ca-server.example.com \
    --known-hosts /etc/ssh_ca/ca_known_hosts
```

The script prints the certificate details via `ssh-keygen -L` on success.

### Manual alternative

If the script is not available, the same operation can be performed with a raw `ssh` command:

```bash
ssh -i /etc/ssh/ssh_host_ed25519_key \
    -p 2222 \
    webserver@ca-server.example.com \
    sign_host_key \
    > /etc/ssh/ssh_host_ed25519_key-cert.pub
```

---

## Configure sshd

Tell sshd to present the certificate by adding the following to `/etc/ssh/sshd_config`:

```
HostKey         /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

If you did not pass `--reload` to the script, reload sshd manually:

```bash
sudo systemctl reload sshd
```

---

## Automate renewal with a systemd timer

Host certificates expire. Create a systemd service and timer to renew automatically.

`/etc/systemd/system/ssh-host-cert-renew.service`:

```ini
[Unit]
Description=Renew SSH host certificate from CA

[Service]
Type=oneshot
ExecStart=/usr/sbin/ssh-ca-sign-host-key \
    -s ca-server.example.com \
    --reload
```

> If you installed manually to `/usr/local/bin/`, adjust the `ExecStart` path accordingly.

`/etc/systemd/system/ssh-host-cert-renew.timer`:

```ini
[Unit]
Description=Renew SSH host certificate daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-host-cert-renew.timer
```

---

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.
