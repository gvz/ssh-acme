# Setup Guide

This guide walks through building the SSH Certificate Authority server from source and running it on a Linux system.

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Get the source](#2-get-the-source)
3. [Build](#3-build)
4. [Generate keys](#4-generate-keys)
5. [Create the configuration](#5-create-the-configuration)
6. [Configure PAM](#6-configure-pam)
7. [Run the server](#7-run-the-server)
8. [Run as a systemd service](#8-run-as-a-systemd-service)
9. [Trust the CA on clients](#9-trust-the-ca-on-clients)
10. [Install the client scripts](#10-install-the-client-scripts)
11. [Request a user certificate](#11-request-a-user-certificate)
12. [Request a host certificate](#12-request-a-host-certificate)

---

## 1. Prerequisites

### Without Nix

Install the following with your distribution's package manager.

**Debian / Ubuntu:**
```bash
sudo apt install build-essential pkg-config libpam-dev libssl-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install gcc pkg-config pam-devel openssl-devel
```

Then install Rust via [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### With Nix (recommended)

The repository ships a Nix flake that provides a fully reproducible dev environment with all dependencies pinned.

```bash
nix develop
```

If you use [direnv](https://direnv.net/), run `direnv allow` once in the repository root and the shell will activate automatically on every subsequent `cd`.

---

## 2. Get the source

```bash
git clone https://github.com/your-org/ssh_ca_server.git
cd ssh_ca_server
```

---

## 3. Build

```bash
cargo build --release
```

The compiled binary is placed at `target/release/ssh_ca_server`.

Optionally, copy it to a system-wide location:
```bash
sudo cp target/release/ssh_ca_server /usr/local/bin/ssh_ca_server
```

---

## 4. Generate keys

The server needs two separate keys:

| Key | Purpose |
|---|---|
| **SSH host key** | Identifies the CA server to connecting clients (standard SSH host key) |
| **CA signing key** | Signs user and host certificates issued by this CA |

### SSH host key

If the server will run as a dedicated service user, generate the host key in a suitable location:

```bash
sudo mkdir -p /etc/ssh_ca
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host"
```

### CA signing key

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh_ca/ca_key -N "" -C "ssh_ca"
```

> **Security:** The CA private key (`ca_key`) must be readable only by the user running the server. Keep it off shared or world-readable filesystems.

```bash
sudo chmod 600 /etc/ssh_ca/ca_key
```

### (Optional) Sign the server's own host key

If you want clients to trust the CA server's host key via the CA (instead of TOFU), sign it:

```bash
sudo ssh-keygen -s /etc/ssh_ca/ca_key \
    -h \
    -I "ssh_ca_server" \
    -n "ssh_ca_server" \
    -V +3650d \
    /etc/ssh/ssh_ca_host_ed25519_key.pub
```

This produces `/etc/ssh/ssh_ca_host_ed25519_key-cert.pub`. Set the `certificate` field in `[ssh]` to use it (see [Section 5](#5-create-the-configuration)).

---

## 5. Create the configuration

Create the directory layout:

```bash
sudo mkdir -p /etc/ssh_ca/hosts
```

### Main config file

Create `/etc/ssh_ca/config.toml`:

```toml
[ssh]
bind = "0.0.0.0"
port = 2222
private_key = "/etc/ssh/ssh_ca_host_ed25519_key"
# Remove or comment out the line below if you did not sign the host key in step 4
certificate = "/etc/ssh/ssh_ca_host_ed25519_key-cert.pub"

[ca]
ca_key             = "/etc/ssh_ca/ca_key"
user_list_file     = "/etc/ssh_ca/user.toml"
default_user_template = "/etc/ssh_ca/user_default.toml"
host_inventory     = "/etc/ssh_ca/hosts/"

[identity_handlers]
user_authenticators = ["pam"]
```

### User list

Create `/etc/ssh_ca/user.toml`. List every user who is allowed to request a certificate and point to their template file. Users not listed here receive the default template.

```toml
[users]
alice = "./alice.toml"
bob   = "./bob.toml"
```

Paths are relative to the directory containing `user.toml` (i.e. `/etc/ssh_ca/`).

### Default user certificate template

Create `/etc/ssh_ca/user_default.toml`. The variable `user_name` is substituted with the authenticated username at signing time.

```toml
validity_in_days = 7
principals = ["{{ user_name }}"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
    "permit-x11-forwarding",
    "permit-user-rc",
]
```

### Per-user certificate template (optional)

Create `/etc/ssh_ca/alice.toml` to override the defaults for a specific user:

```toml
validity_in_days = 1
principals = ["alice", "alice-sudo"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
]
```

### Host inventory entry

For each host that should receive a signed host certificate, create a TOML file in `/etc/ssh_ca/hosts/` named after the hostname.

First, obtain the host's public key:
```bash
# Run this on the host machine
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Then create `/etc/ssh_ca/hosts/<hostname>.toml` on the CA server, replacing `<PUBLIC_KEY>` with the output above:

```toml
# /etc/ssh_ca/hosts/webserver.toml
public_key       = "ssh-ed25519 AAAA<...rest of key...>"
validity_in_days = 365
hostnames        = ["webserver", "webserver.example.com"]
extensions       = []
```

> The filename (without `.toml`) must match the hostname the host uses when authenticating.

---

## 6. Configure PAM

The server authenticates users via PAM using the `login` service. On most distributions this works out of the box. Verify that `/etc/pam.d/login` exists and is configured for your system's user database (local accounts, LDAP, etc.).

> **Note:** `root` is always rejected by the server regardless of PAM configuration.

---

## 7. Run the server

### Foreground (for testing)

```bash
RUST_LOG=info ssh_ca_server -c /etc/ssh_ca/config.toml
```

The server starts on the configured port (default `2222`) and automatically spawns the CA as a child process. You should see log lines similar to:

```
[INFO  ssh_ca_server] spawned CA
[INFO  ssh_ca_server::ssh_server] starting ssh server at 0.0.0.0:2222
[INFO  ssh_ca_server::certificat_authority::ca_server] CA server listening on /tmp/...
```

Press `Ctrl-C` to stop. The CA child process and socket file are cleaned up automatically.

### Advanced: run CA and SSH server as separate processes

Start the CA server first, pointing it at a fixed socket path:

```bash
RUST_LOG=info ssh_ca_server \
    -c /etc/ssh_ca/config.toml \
    --certificate-authority \
    --socket-path /run/ssh_ca/ca.sock
```

Then start the SSH server, telling it not to spawn its own CA:

```bash
RUST_LOG=info ssh_ca_server \
    -c /etc/ssh_ca/config.toml \
    --socket-path /run/ssh_ca/ca.sock \
    --disable-ca
```

---

## 8. Run as a systemd service

Create `/etc/systemd/system/ssh-ca-server.service`:

```ini
[Unit]
Description=SSH Certificate Authority
After=network.target

[Service]
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ssh_ca_server -c /etc/ssh_ca/config.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-ca-server.service
sudo systemctl status ssh-ca-server.service
```

Check logs:

```bash
journalctl -u ssh-ca-server.service -f
```

---

## 9. Trust the CA on clients

Clients must be told to trust certificates signed by this CA. Add the following line to `/etc/ssh/ssh_known_hosts` (system-wide) or `~/.ssh/known_hosts` (per user) on each client machine:

```
@cert-authority * <contents of /etc/ssh_ca/ca_key.pub>
```

Example — copy the CA public key from the server and install it on a client:

```bash
# On the CA server
cat /etc/ssh_ca/ca_key.pub

# On the client — append to the system known_hosts
echo "@cert-authority * $(cat ca_key.pub)" | sudo tee -a /etc/ssh/ssh_known_hosts
```

---

## 10. Install the client scripts

The repository ships two Bash scripts in the `clients/` directory that wrap the raw SSH commands with argument parsing, input validation, retry logic, and certificate verification.

| Script | Purpose |
|---|---|
| `ssh-ca-sign-user-key.sh` | Request a signed user certificate (password auth) |
| `ssh-ca-sign-host-key.sh` | Request a signed host certificate (public key auth) |

Copy them to a directory on `$PATH` on each machine that needs them:

```bash
# On a user's workstation
sudo cp clients/ssh-ca-sign-user-key.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/ssh-ca-sign-user-key.sh

# On each managed host
sudo cp clients/ssh-ca-sign-host-key.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/ssh-ca-sign-host-key.sh
```

Both scripts require only `bash`, `ssh`, and `ssh-keygen` (standard on any Linux system). `getopt` from `util-linux` is also required and is present by default on all major distributions.

---

## 11. Request a user certificate

Run `ssh-ca-sign-user-key.sh` on the user's workstation. The script authenticates with the user's password (PAM), sends the public key to the CA, and writes the signed certificate to disk. You will be prompted for your password interactively.

```bash
ssh-ca-sign-user-key.sh -s ca-server.example.com
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
ssh-ca-sign-user-key.sh -s ca-server.example.com

# Sign a specific key as a named user
ssh-ca-sign-user-key.sh -s ca-server.example.com -u alice -k ~/.ssh/id_ed25519.pub

# Custom port, explicit output path, verbose logging
ssh-ca-sign-user-key.sh -s ca-server.example.com -p 2222 \
    -o ~/.ssh/id_ed25519-cert.pub -v

# Retry up to 3 times with a 10-second delay between attempts
ssh-ca-sign-user-key.sh -s ca-server.example.com --retry 3 --retry-delay 10
```

The script prints the certificate details via `ssh-keygen -L` on success.

### Configure the SSH client

Add the following to `~/.ssh/config` so the certificate is presented automatically:

```
Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile    ~/.ssh/id_ed25519
```

### Manual alternative

If the script is not available, the same operation can be performed with a raw `ssh` command:

```bash
ssh -T -p 2222 alice@ca-server.example.com \
    < ~/.ssh/id_ed25519.pub \
    > ~/.ssh/id_ed25519-cert.pub
```

---

## 12. Request a host certificate

Run `ssh-ca-sign-host-key.sh` on the host that needs a signed certificate. The script authenticates using the host's private key (public key auth), requests signing, and writes the certificate to disk. The host's public key must already be registered in the CA's host inventory (see [Section 5](#5-create-the-configuration)).

```bash
sudo ssh-ca-sign-host-key.sh -s ca-server.example.com
```

This signs `/etc/ssh/ssh_host_ed25519_key` and writes the certificate to `/etc/ssh/ssh_host_ed25519_key-cert.pub`. Root (or equivalent) is required to read the host private key.

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
sudo ssh-ca-sign-host-key.sh -s ca-server.example.com

# Sign a specific key, reload sshd automatically when done
sudo ssh-ca-sign-host-key.sh -s ca-server.example.com \
    -i /etc/ssh/ssh_host_ed25519_key --reload

# Custom port, explicit hostname, retry on failure
sudo ssh-ca-sign-host-key.sh -s ca-server.example.com -p 2222 \
    -n webserver --retry 3

# Use a dedicated known_hosts file for the CA server
sudo ssh-ca-sign-host-key.sh -s ca-server.example.com \
    --known-hosts /etc/ssh_ca/ca_known_hosts
```

### Configure sshd

Tell sshd to present the certificate by adding to `/etc/ssh/sshd_config`:

```
HostKey         /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

If you did not pass `--reload`, reload sshd manually:

```bash
sudo systemctl reload sshd
```

### Automating renewal with a systemd timer

Host certificates expire. Create a systemd service and timer to renew automatically.

`/etc/systemd/system/ssh-host-cert-renew.service`:

```ini
[Unit]
Description=Renew SSH host certificate from CA

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ssh-ca-sign-host-key.sh \
    -s ca-server.example.com \
    --reload
```

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

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.
