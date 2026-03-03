# SSH ACME Server — Documentation Overview

SSH ACME Server is a self-hosted SSH Certificate Authority. It lets you issue short-lived, cryptographically signed SSH certificates for both users and hosts — similar to Let's Encrypt, but for SSH.

Pre-built Debian packages for the server and client are published on every [GitHub Release](https://github.com/your-org/ssh_acme_server/releases). Building from source is also supported on any Linux system.

## How it works

All communication between machines happens over SSH. The CA server listens on a dedicated port and signs certificates on request. Users authenticate with a password (PAM); hosts authenticate with their existing SSH host key.

## Three roles, three guides

There are three distinct roles in this system. Follow the guide for your role.

| Role | Who | Guide |
|---|---|---|
| **CA operator** | Runs and maintains the CA server | [CA Server Setup](setup-ca.md) |
| **Host admin** | Enrolls a server to receive a signed host certificate | [Host Setup](setup-host.md) |
| **User** | Obtains a signed certificate for their own SSH key | [User Setup](setup-user.md) |

## Typical setup order

1. The **CA operator** follows [CA Server Setup](setup-ca.md) to build, configure, and start the CA.
2. The CA operator adds each host's public key to the host inventory (covered in [CA Server Setup](setup-ca.md)).
3. Each **host admin** follows [Host Setup](setup-host.md) to request a signed host certificate and configure sshd.
4. Each **user** follows [User Setup](setup-user.md) to trust the CA and request a signed user certificate.

## Disclaimer

Parts of the code and documentation in this project were implemented with the assistance of AI tools.
