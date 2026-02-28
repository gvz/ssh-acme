# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.1.0] - 2024-02-28

### Added
- SSH Certificate Authority server with PAM authentication
- Pluggable authentication system (currently supports PAM)
- Host certificate signing with inventory-based public key verification
- Unix socket IPC for secure communication between SSH server and CA
- Configurable certificate templates using MiniJinja (Jinja2-compatible)
- Dynamic per-user certificate templates with fallback to defaults
- Client scripts for requesting user and host certificates
- Debian packages for easy installation (server and client)
- NixOS module for declarative server configuration
- Comprehensive end-to-end tests using NixOS VMs
- Docker-based testing infrastructure
- Fuzzing harness using AFL++
- Root user blocking for enhanced security
- Systemd service integration

### Security
- Password-based authentication for user certificates via PAM
- Public key authentication for host certificates
- Inventory-based host verification to prevent unauthorized certificates
- Explicit root user blocking in authentication flow
- Short-lived certificates (7-day default validity)
