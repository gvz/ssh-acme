# CA Server Setup

This guide is for the operator who will run the SSH Certificate Authority server. By the end you will have a running CA that can sign user and host certificates.

**Audience:** system administrator setting up the CA for the first time.

There are two ways to install the server: from a pre-built Debian package (recommended for Debian/Ubuntu) or from source.

## Table of Contents

- [Option A: Install from the Debian package](#option-a-install-from-the-debian-package)
  1. [Download and install the package](#1-download-and-install-the-package)
  2. [What the package sets up automatically](#2-what-the-package-sets-up-automatically)
  3. [Complete the configuration](#3-complete-the-configuration)
- [Option B: Build from source](#option-b-build-from-source)
  1. [Prerequisites](#1-prerequisites)
  2. [Get the source](#2-get-the-source)
  3. [Build](#3-build)
  4. [Generate keys](#4-generate-keys)
  5. [Create the configuration](#5-create-the-configuration)
  6. [Configure PAM](#6-configure-pam)
  7. [Run the server](#7-run-the-server)
  8. [Run as a systemd service](#8-run-as-a-systemd-service)

---

## Option A: Install from the Debian package

Pre-built `.deb` packages are published as assets on every [GitHub Release](https://github.com/your-org/ssh_acme_server/releases). This is the fastest way to get started on Debian or Ubuntu.

> **Note:** packages are built for `amd64` only. For other architectures, follow [Option B](#option-b-build-from-source).

### 1. Download and install the package

Go to the [latest release](https://github.com/your-org/ssh_acme_server/releases/latest) and download `ssh-ca-server_<version>_amd64.deb`. Then install it:

```bash
sudo dpkg -i ssh-ca-server_<version>_amd64.deb
sudo apt-get install -f   # resolves any missing dependencies (libpam0g, openssh-client)
```

### 2. What the package sets up automatically

The package `postinst` script handles the following on first install:

| What | Where |
|---|---|
| SSH host key (if absent) | `/etc/ssh_ca_server/ssh_ca_host_ed25519_key` |
| CA signing key (if absent) | `/etc/ssh_ca_server/ca_key` |
| Host inventory directory | `/etc/ssh_ca_server/hosts/` |
| Default config file | `/etc/ssh_ca_server/config.toml` |
| Default user list | `/etc/ssh_ca_server/user.toml` |
| Default user certificate template | `/etc/ssh_ca_server/user_default.toml` |
| systemd service (enabled + started) | `ssh-ca-server.service` |

The server binary is installed to `/usr/bin/ssh_ca_server`.

### 3. Complete the configuration

The package installs working defaults, but you still need to configure who can request certificates and which hosts are enrolled.

#### User list

Edit `/etc/ssh_ca_server/user.toml` to list users who may request certificates. Users not listed receive the default template.

```toml
[users]
alice = "./alice.toml"
bob   = "./bob.toml"
```

Paths are relative to `/etc/ssh_ca_server/`.

#### Per-user certificate template (optional)

Create `/etc/ssh_ca_server/alice.toml` to override the defaults for a specific user:

```toml
validity_in_days = 1
principals = ["alice", "alice-sudo"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
]
```

#### Default user certificate template

The installed default at `/etc/ssh_ca_server/user_default.toml` grants a 7-day certificate with standard extensions. Edit it if you want different defaults:

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

#### Host inventory entry

For each host that should receive a signed host certificate, create a TOML file in `/etc/ssh_ca_server/hosts/` named after the hostname.

First, obtain the host's public key:
```bash
# Run this on the host machine
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Then create `/etc/ssh_ca_server/hosts/<hostname>.toml` on the CA server, replacing `<PUBLIC_KEY>` with the output above:

```toml
# /etc/ssh_ca_server/hosts/webserver.toml
public_key       = "ssh-ed25519 AAAA<...rest of key...>"
validity_in_days = 365
hostnames        = ["webserver", "webserver.example.com"]
extensions       = []
```

> The filename (without `.toml`) must match the hostname the host uses when authenticating.

#### (Optional) Sign the server's own host key

If you want clients to trust the CA server's host key via the CA (instead of TOFU), sign it:

```bash
sudo ssh-keygen -s /etc/ssh_ca_server/ca_key \
    -h \
    -I "ssh_ca_server" \
    -n "ssh_ca_server" \
    -V +3650d \
    /etc/ssh_ca_server/ssh_ca_host_ed25519_key.pub
```

This produces `/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub`. Then uncomment the `certificate` line in `/etc/ssh_ca_server/config.toml`:

```toml
certificate = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub"
```

Reload the service to apply any configuration changes:

```bash
sudo systemctl restart ssh-ca-server.service
sudo systemctl status ssh-ca-server.service
```

Check logs:

```bash
journalctl -u ssh-ca-server.service -f
```

---

## Option B: Build from source

### 1. Prerequisites

#### Without Nix

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

#### With Nix (recommended)

The repository ships a Nix flake that provides a fully reproducible dev environment with all dependencies pinned.

```bash
nix develop
```

If you use [direnv](https://direnv.net/), run `direnv allow` once in the repository root and the shell will activate automatically on every subsequent `cd`.

---

### 2. Get the source

```bash
git clone https://github.com/your-org/ssh_acme_server.git
cd ssh_acme_server
```

---

### 3. Build

```bash
cargo build --release
```

The compiled binary is placed at `target/release/ssh_ca_server`.

Optionally, copy it to a system-wide location:
```bash
sudo cp target/release/ssh_ca_server /usr/local/bin/ssh_ca_server
```

---

### 4. Generate keys

The server needs two separate keys:

| Key | Purpose |
|---|---|
| **SSH host key** | Identifies the CA server to connecting clients (standard SSH host key) |
| **CA signing key** | Signs user and host certificates issued by this CA |

#### SSH host key

```bash
sudo mkdir -p /etc/ssh_ca
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host"
```

#### CA signing key

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh_ca/ca_key -N "" -C "ssh_ca"
```

> **Security:** The CA private key (`ca_key`) must be readable only by the user running the server. Keep it off shared or world-readable filesystems.

```bash
sudo chmod 600 /etc/ssh_ca/ca_key
```

#### (Optional) Sign the server's own host key

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

### 5. Create the configuration

Create the directory layout:

```bash
sudo mkdir -p /etc/ssh_ca/hosts
```

#### Main config file

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

#### User list

Create `/etc/ssh_ca/user.toml`. List every user who is allowed to request a certificate and point to their template file. Users not listed here receive the default template.

```toml
[users]
alice = "./alice.toml"
bob   = "./bob.toml"
```

Paths are relative to the directory containing `user.toml` (i.e. `/etc/ssh_ca/`).

#### Default user certificate template

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

#### Per-user certificate template (optional)

Create `/etc/ssh_ca/alice.toml` to override the defaults for a specific user:

```toml
validity_in_days = 1
principals = ["alice", "alice-sudo"]
extensions = [
    "permit-pty",
    "permit-agent-forwarding",
]
```

#### Host inventory entry

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

### 6. Configure PAM

The server authenticates users via PAM using the `login` service. On most distributions this works out of the box. Verify that `/etc/pam.d/login` exists and is configured for your system's user database (local accounts, LDAP, etc.).

> **Note:** `root` is always rejected by the server regardless of PAM configuration.

---

### 7. Run the server

#### Foreground (for testing)

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

#### Advanced: run CA and SSH server as separate processes

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

### 8. Run as a systemd service

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

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.
