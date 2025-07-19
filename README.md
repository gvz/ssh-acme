# SSH ACME Server

This project aims to provide a self-hosted SSH Certificate Authority (CA) similar to Let's Encrypt, but for SSH certificates. It allows users to obtain and manage SSH certificates for their machines, enhancing security by leveraging short-lived, automatically renewed certificates instead of long-lived SSH keys.

## Features

- **SSH Certificate Authority:** A built-in CA that signs SSH public keys into certificates.
- **Pluggable Authentication:** Supports different authentication methods for users requesting certificates (currently PAM).
- **Unix Socket Communication:** The SSH server communicates with the CA server via a Unix socket for secure and efficient inter-process communication.
- **Configurable:** Easily configurable via TOML files for SSH server settings, CA settings, and user-specific certificate templates.
- **Dynamic User Templates:** User certificate templates can be dynamically generated using Jinja2, allowing for flexible principal and extension management.

## Project Structure

- `src/main.rs`: The main entry point of the application.
- `src/lib.rs`: Contains the core logic, including command-line argument parsing and the `run_server` function that orchestrates the SSH and CA servers.
- `src/certificat_authority/`:
    - `mod.rs`: Defines the `CertificateAuthority` struct and its core logic for signing certificates.
    - `ca_client.rs`: Implements the client-side communication with the CA server over a Unix socket.
    - `ca_server.rs`: Implements the server-side logic for the CA, listening for signing requests.
    - `config.rs`: Defines the configuration structure for the Certificate Authority.
    - `user_defaults_reader.rs`: Handles reading and parsing user-specific certificate templates.
- `src/config/`:
    - `mod.rs`: Defines the main `Config` structure and handles reading the overall configuration file.
- `src/identiy_handlers/`:
    - `mod.rs`: Defines the `UserAuthenticator` trait and the `Credential` enum for pluggable authentication.
    - `pam_auth.rs`: Provides a PAM-based user authenticator.
- `src/ssh_server/`:
    - `mod.rs`: Implements the SSH server logic, handling client connections, authentication, and certificate requests.
    - `config.rs`: Defines the configuration structure for the SSH server.
- `config/`: Example configuration files.
- `test_data/`: Test data, including example keys and user certificate configurations.

## Getting Started

### Prerequisites

- Rust (latest stable version recommended)
- `libpam-dev` (or equivalent for your Linux distribution) for PAM authentication.

### Building

To build the project, navigate to the project root and run:

```bash
cargo build
```

### Running

The server can be run in two modes: as a combined SSH and CA server, or as a standalone CA server.

#### Running as Combined SSH and CA Server

This is the default mode. The SSH server will spawn the CA server as a child process and communicate with it via a Unix socket.

```bash
cargo run -- -c config/config.toml
```

#### Running as Standalone CA Server

You can run the CA server independently. This is useful for debugging or if you want to manage the CA process separately.

```bash
cargo run -- -c config/config.toml -a -s /tmp/ssh_acme_ca.sock
```

Replace `/tmp/ssh_acme_ca.sock` with your desired socket path.

### Configuration

The main configuration file is `config/config.toml`. It defines:

- `[ssh]`: SSH server binding address, port, and private key path.
- `[ca]`: CA private key path, user list file, and default user template.
- `[identity_handlers]`: List of enabled user authenticators (e.g., `["pam"]`).

User-specific certificate templates are defined in TOML files and can use Jinja2 templating for dynamic values.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
