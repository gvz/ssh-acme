{
  pkgs,
  lib,
  app,
  system,
}:
let
  debArch =
    {
      "x86_64-linux" = "amd64";
      "aarch64-linux" = "arm64";
      "i686-linux" = "i386";
      "armv7l-linux" = "armhf";
    }
    .${system} or (builtins.throw "Unsupported system for .deb: ${system}");

  version = "0.1.0";

  control = pkgs.writeText "control" (
    lib.concatStringsSep "\n" [
      "Package: ssh-ca-server"
      "Version: ${version}"
      "Section: net"
      "Priority: optional"
      "Architecture: ${debArch}"
      "Depends: libpam0g, openssh-client"
      "Maintainer: SSH CA Project"
      "Description: SSH Certificate Authority Server"
      " A self-hosted SSH certificate authority server, similar to"
      " Let's Encrypt but for SSH certificates. Authenticates users"
      " via PAM and signs SSH user and host certificates."
      ""
    ]
  );

  conffiles = pkgs.writeText "conffiles" (
    lib.concatStringsSep "\n" [
      "/etc/ssh_ca_server/config.toml"
      "/etc/ssh_ca_server/user.toml"
      "/etc/ssh_ca_server/user_default.toml"
      ""
    ]
  );

  postinst = pkgs.writeText "postinst" ''
    #!/bin/bash
    set -e

    # Generate SSH host key for the CA server (if not already present)
    if [ ! -f /etc/ssh_ca_server/ssh_ca_host_ed25519_key ]; then
        ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ssh_ca_host_ed25519_key -N "" -C "ssh_ca_host"
        chmod 600 /etc/ssh_ca_server/ssh_ca_host_ed25519_key
    fi

    # Generate CA signing key (if not already present)
    if [ ! -f /etc/ssh_ca_server/ca_key ]; then
        ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ca_key -N "" -C "ssh_ca"
        chmod 600 /etc/ssh_ca_server/ca_key
    fi

    # Create hosts directory if missing
    mkdir -p /etc/ssh_ca_server/hosts

    # Enable and start the service
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable ssh-ca-server.service
        systemctl start ssh-ca-server.service
    fi
  '';

  prerm = pkgs.writeText "prerm" ''
    #!/bin/bash
    set -e
    if [ -d /run/systemd/system ]; then
        systemctl stop ssh-ca-server.service || true
    fi
  '';

  postrm = pkgs.writeText "postrm" ''
    #!/bin/bash
    set -e
    if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then
        if [ -d /run/systemd/system ]; then
            systemctl disable ssh-ca-server.service || true
            systemctl daemon-reload
        fi
    fi
  '';

  configToml = pkgs.writeText "config.toml" ''
    [ssh]
    bind = "0.0.0.0"
    port = 2222
    private_key = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key"
    # Uncomment after signing the host key with the CA:
    # certificate = "/etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub"

    [ca]
    ca_key = "/etc/ssh_ca_server/ca_key"
    user_list_file = "/etc/ssh_ca_server/user.toml"
    default_user_template = "/etc/ssh_ca_server/user_default.toml"
    host_inventory = "/etc/ssh_ca_server/hosts/"

    [identity_handlers]
    user_authenticators = ["pam"]
  '';

  userToml = pkgs.writeText "user.toml" ''
    # Map usernames to per-user certificate template files.
    # Users not listed here receive the default template.
    # Paths are relative to this file's directory.
    #
    # [users]
    # alice = "./alice.toml"
    # bob = "./bob.toml"

    [users]
  '';

  userDefaultToml = pkgs.writeText "user_default.toml" ''
    validity_in_days = 7
    principals = ["{{ user_name }}"]
    extensions = [
        "permit-pty",
        "permit-agent-forwarding",
        "permit-x11-forwarding",
        "permit-user-rc",
    ]

    [critical_options]
  '';

  serviceFile = pkgs.writeText "ssh-ca-server.service" ''
    [Unit]
    Description=SSH Certificate Authority Server
    After=network.target

    [Service]
    Environment=RUST_LOG=info
    ExecStart=/usr/bin/ssh_ca_server -c /etc/ssh_ca_server/config.toml
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
  '';
in
pkgs.stdenv.mkDerivation {
  pname = "ssh-ca-server-deb";
  inherit version;
  src = ./..;

  nativeBuildInputs = [
    pkgs.dpkg
    pkgs.patchelf
  ];

  dontBuild = true;

  installPhase = ''
    mkdir -p "$out"
    mkdir -p pkg/DEBIAN
    mkdir -p pkg/usr/bin
    mkdir -p pkg/etc/ssh_ca_server/hosts
    mkdir -p pkg/lib/systemd/system

    # DEBIAN metadata
    cp ${control} pkg/DEBIAN/control
    cp ${conffiles} pkg/DEBIAN/conffiles

    cp ${postinst} pkg/DEBIAN/postinst
    chmod 0755 pkg/DEBIAN/postinst

    cp ${prerm} pkg/DEBIAN/prerm
    chmod 0755 pkg/DEBIAN/prerm

    cp ${postrm} pkg/DEBIAN/postrm
    chmod 0755 pkg/DEBIAN/postrm

    # Server binary -- patch away Nix-store interpreter & rpath so
    # the binary works on regular Debian/Ubuntu systems.
    cp ${app}/bin/ssh_ca_server pkg/usr/bin/ssh_ca_server
    chmod 0755 pkg/usr/bin/ssh_ca_server
    patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
             --remove-rpath \
             pkg/usr/bin/ssh_ca_server

    # Default configuration files
    cp ${configToml} pkg/etc/ssh_ca_server/config.toml
    cp ${userToml} pkg/etc/ssh_ca_server/user.toml
    cp ${userDefaultToml} pkg/etc/ssh_ca_server/user_default.toml

    # systemd service
    cp ${serviceFile} pkg/lib/systemd/system/ssh-ca-server.service

    dpkg-deb --root-owner-group --build pkg "$out/ssh-ca-server_${version}_${debArch}.deb"
  '';
}
