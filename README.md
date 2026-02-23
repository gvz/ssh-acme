# SSH Certificate Authority

This project provides a self-hosted SSH Certificate Authority (CA), similar in spirit to Let's Encrypt but for SSH certificates. Machines and users connect to this server over SSH to obtain short-lived, automatically renewable SSH certificates — replacing long-lived static keys.

## Features

- **SSH Certificate Authority:** A built-in CA that signs SSH public keys into user or host certificates.
- **Pluggable Authentication:** Supports different authentication methods for users requesting certificates (currently PAM). `root` is explicitly blocked.
- **Host Certificate Signing:** Hosts authenticate with their public key (verified against a pre-registered inventory) and receive a signed host certificate.
- **Unix Socket IPC:** The SSH server and CA server communicate over a Unix socket for secure inter-process communication.
- **Configurable:** Configured via TOML files for SSH server settings, CA settings, and per-user certificate templates.
- **Dynamic User Templates:** User certificate templates are rendered with [MiniJinja](https://docs.rs/minijinja) (Jinja2-compatible), allowing flexible principal and extension management per user.

## Project Structure

```
src/
├── main.rs                               # Entry point
├── lib.rs                                # CLI argument parsing and server orchestration
├── config/
│   └── mod.rs                            # Top-level config struct and file reader
├── certificat_authority/
│   ├── mod.rs                            # CertificateAuthority struct; sign_certificate / sign_host_certificate
│   ├── ca_client.rs                      # Unix socket client — sends requests to the CA server
│   ├── ca_server.rs                      # Unix socket server — receives and dispatches signing requests
│   ├── config.rs                         # CA configuration struct
│   ├── user_defaults_reader.rs           # Reads and renders per-user certificate templates
│   ├── host_config_reader.rs             # Reads host inventory TOML files; matches keys to hosts
│   └── certificat_template_reader.rs     # Low-level Jinja-templated TOML config reader
├── ssh_server/
│   ├── mod.rs                            # SSH server, connection handler, auth dispatch
│   ├── config.rs                         # SSH server configuration struct
│   ├── user_key_signer.rs                # Handles user certificate signing requests (password auth flow)
│   └── host_key_signer.rs                # Handles host certificate signing requests (public key auth flow)
└── identiy_handlers/
    ├── mod.rs                            # UserAuthenticator trait and authenticator setup
    └── pam_auth.rs                       # PAM-based authenticator

config/                                   # Example configuration files
tests/                                    # Integration and end-to-end tests
full_fuzz/                                # AFL++ fuzzing harness
```

## Getting Started

### Prerequisites

- **Rust** (latest stable) — or use the provided Nix dev shell (see below)
- **libpam-dev** (or equivalent for your distribution) for PAM authentication

#### Using the Nix dev shell (recommended)

The repository ships a Nix flake. If you have Nix with flakes enabled:

```bash
nix develop
```

[direnv](https://direnv.net/) is also configured — `direnv allow` will activate the shell automatically.

### Building

```bash
cargo build --release
```

### Running

The binary has two modes, controlled by CLI flags.

#### Combined mode (default)

Starts the SSH server and automatically spawns the CA server as a child process. The socket path is generated automatically in a temporary directory.

```bash
cargo run -- -c config/config.toml
```

#### Standalone CA server

Runs only the CA server, listening on the specified Unix socket. Useful for running the CA as a separate process or service.

```bash
cargo run -- -c config/config.toml --certificate-authority --socket-path /run/ssh_acme/ca.sock
```

#### SSH server with an external CA

Run the SSH server without spawning its own CA process (e.g. when the CA is managed by a separate systemd unit):

```bash
cargo run -- -c config/config.toml --socket-path /run/ssh_acme/ca.sock --disable-ca
```

### CLI flags

| Flag                      | Short | Description                                                                 |
|---------------------------|-------|-----------------------------------------------------------------------------|
| `--config-file <PATH>`    | `-c`  | Path to the TOML configuration file (**required**)                          |
| `--certificate-authority` | `-a`  | Run as a standalone CA server                                               |
| `--socket-path <PATH>`    | `-s`  | Unix socket path for CA communication (auto-generated if omitted)           |
| `--disable-ca`            |       | Start the SSH server without spawning a CA child process                    |

## Configuration

### Main config (`config/config.toml`)

```toml
[ssh]
bind = "0.0.0.0"
port = 2222
private_key = "/etc/ssh/ssh_host_ed25519_key"
# Optional: path to the server's own signed host certificate
certificate = "/etc/ssh/ssh_host_ed25519_key-cert.pub"

[ca]
ca_key = "/etc/ssh_acme/ca_key"
user_list_file = "/etc/ssh_acme/user.toml"
default_user_template = "/etc/ssh_acme/user_default.toml"
host_inventory = "/etc/ssh_acme/hosts/"

[identity_handlers]
user_authenticators = ["pam"]
```

Relative paths in `[ca]` are resolved relative to the directory containing the config file.

### User list (`user_list_file`)

Maps usernames to their certificate template files. Paths are relative to the user list file itself.

```toml
[users]
alice = "./alice_template.toml"
bob   = "./bob_template.toml"
# Users not listed here receive the default_user_template
```

### User certificate template

Templates are TOML files rendered with MiniJinja. The variable `user_name` holds the authenticated username.

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

### Host inventory (`host_inventory`)

One TOML file per host, named `<hostname>.toml`, placed in the `host_inventory` directory.

```toml
# config/hosts/webserver.toml
public_key = "ssh-ed25519 AAAA..."
validity_in_days = 365
hostnames = ["webserver", "webserver.example.com"]
extensions = []
```

## How It Works

### User Certificate Flow

1. A user connects to the SSH ACME server with their **username and password**.
2. The server authenticates the user against the configured identity handlers (e.g. PAM). `root` is always rejected.
3. On success, the user sends their **SSH public key** as channel data (stdin).
4. The SSH server forwards a `SignCertificate` request to the CA server over the Unix socket.
5. The CA looks up the user's certificate template (falling back to the default template), renders it, and signs the public key.
6. The signed certificate is returned to the user over the same SSH channel.

### Host Certificate Flow

1. A host connects to the SSH ACME server using **public key authentication**, presenting its host public key.
2. The server checks the CA's host inventory for a matching public key entry. If no match is found, the connection is rejected.
3. The host sends the `sign_host_key` command over the exec channel.
4. The SSH server forwards a `SignHostCertificate` request to the CA server.
5. The CA verifies the public key against the host's inventory entry and signs it.
6. The signed host certificate is returned to the host over the same SSH channel.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.
