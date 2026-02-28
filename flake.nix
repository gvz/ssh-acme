{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      naersk,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
        lib = nixpkgs.lib;
        russh-src = pkgs.fetchgit {
          url = "https://github.com/gvz/russh.git";
          rev = "1fe6853";
          hash = "sha256-UYrFXRLhqW7cV3CBHVURebNlFjVh4Iopf6keMAVrhUI=";
        };

        # The package containing your application binary
        common = {
          pname = "ssh_ca_server";
          version = "0.1.0"; # You can manage this version as you see fit

          release = true;

          src = ./.;
          buildInputs = with pkgs; [
            llvm
            clang
            libclang
            llvmPackages.libclang.lib
            lldb
            pkg-config
            systemd
            pcsclite
            pam
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          postPatch = ''
            substituteInPlace Cargo.toml \
                --replace 'git = "https://github.com/gvz/russh.git"' \
                          'path = "${russh-src}/russh"'
                cat Cargo.toml
          '';
        };

        app = naersk-lib.buildPackage (common // { doCheck = false; });
        # this only exists to be able to run all test run with "cargo test" also in "nix flake test"
        test_app = naersk-lib.buildPackage (
          common
          // {
            doCheck = true;
            cargoTestOptions = x: x ++ [ "--features test_auth" ];
          }
        );
        # The NixOS module that provides the systemd service
        sshCaServerModule =
          { config, ... }:
          {
            options.services.ssh-ca-server = {
              enable = lib.mkEnableOption "ssh-ca-server";

              configFile = lib.mkOption {
                type = lib.types.path;
                default = "/etc/ssh_ca_server/config.toml";
                description = "Path to the ssh-ca-server configuration file.";
              };

              dataDir = lib.mkOption {
                type = lib.types.path;
                default = "/var/lib/ssh-ca-server";
                description = "The data directory for the ssh-ca-server.";
              };
            };

            config = lib.mkIf config.services.ssh-ca-server.enable {
              # Create a dedicated user for the service

              systemd.services.ssh-ca-server = {
                description = "SSH Certificate Authority Server";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                serviceConfig = {
                  Environment = "RUST_LOG=debug";
                  ExecStart = ''
                    ${app}/bin/ssh_ca_server -c ${config.services.ssh-ca-server.configFile}
                  '';

                  Restart = "no";
                  # Creates /var/lib/ssh-ca-server with correct ownership
                  StateDirectory = "ssh-ca-server";
                };
              };
            };
          };
        # Debian package containing the client scripts
        deb-client = pkgs.stdenv.mkDerivation {
          pname = "ssh-ca-client-deb";
          version = "0.1.0";
          src = ./clients;

          nativeBuildInputs = [ pkgs.dpkg ];

          dontBuild = true;

          installPhase =
            let
              control = pkgs.writeText "control" (
                lib.concatStringsSep "\n" [
                  "Package: ssh-ca-client"
                  "Version: 0.1.0"
                  "Section: net"
                  "Priority: optional"
                  "Architecture: all"
                  "Depends: openssh-client"
                  "Maintainer: SSH CA Project"
                  "Description: Client scripts for SSH Certificate Authority"
                  " Scripts to request signed user and host certificates from"
                  " an SSH CA server."
                  " ssh-ca-sign-user-key requests a signed user certificate (any user)."
                  " ssh-ca-sign-host-key requests a signed host certificate (root only)."
                  ""
                ]
              );
            in
            ''
              mkdir -p "$out"
              mkdir -p pkg/DEBIAN
              mkdir -p pkg/usr/bin
              mkdir -p pkg/usr/sbin

              cp ${control} pkg/DEBIAN/control

              cp "$src/ssh-ca-sign-user-key.sh" pkg/usr/bin/ssh-ca-sign-user-key
              chmod 0755 pkg/usr/bin/ssh-ca-sign-user-key

              cp "$src/ssh-ca-sign-host-key.sh" pkg/usr/sbin/ssh-ca-sign-host-key
              chmod 0755 pkg/usr/sbin/ssh-ca-sign-host-key

              dpkg-deb --root-owner-group --build pkg "$out/ssh-ca-client_0.1.0_all.deb"
            '';
        };

        # Debian package containing the server binary, config, and systemd service
        deb-server =
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
            src = ./.;

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

              # Server binary – patch away Nix-store interpreter & rpath so
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
          };

      in
      {
        # Replaces `defaultPackage` with the standard `packages.default`
        packages = {
          default = app;
          deb-client = deb-client;
          deb-server = deb-server;
        };

        # The old `defaultPackage` for compatibility if needed elsewhere
        defaultPackage = app;

        devShell =
          with pkgs;
          mkShell {
            buildInputs = [
              cargo
              rustc
              rustfmt
              pre-commit
              rustPackages.clippy
              llvm
              clang
              libclang
              llvmPackages.libclang.lib
              lldb
              openssl
              openssl.dev
              rust-analyzer
              cargo-nextest
              pkg-config
              cargo-vet
              cargo-audit
              cargo-fuzz
              systemd
              pcsclite
              pam
              gnumake
              act
            ];
            shellHook = ''
              export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib";
            '';
            RUST_SRC_PATH = rustPlatform.rustLibSrc;
          };

        nixosModules.default = sshCaServerModule;

        checks = {
          cargo-tests = test_app;
          end_to_end_test = import ./tests/end_to_end_test/test.nix {
            inherit nixpkgs;
            sshCaServerModule = sshCaServerModule;
          };
          fuzz-smoke-test =
            let
              fuzzSrc = pkgs.stdenv.mkDerivation {
                name = "fuzz-src";
                src = ./.;
                phases = [
                  "unpackPhase"
                  "patchPhase"
                  "installPhase"
                ];
                postPatch = common.postPatch;
                installPhase = ''
                  # Create a directory layout where the fuzz workspace is at the
                  # root (so naersk finds its Cargo.lock) but the parent crate
                  # is available via the path dependency.
                  mkdir -p $out
                  cp -r . $out/parent
                  # Copy fuzz contents to root level
                  cp fuzz/Cargo.toml $out/Cargo.toml
                  cp fuzz/Cargo.lock $out/Cargo.lock
                  cp -r fuzz/fuzz_targets $out/fuzz_targets
                  # Rewrite the path dependency from ".." to "./parent"
                  substituteInPlace $out/Cargo.toml \
                    --replace-fail 'path = ".."' 'path = "./parent"'
                  # Fix the bin paths
                  substituteInPlace $out/Cargo.toml \
                    --replace-fail 'path = "fuzz_targets/' 'path = "fuzz_targets/'
                '';
              };
            in
            naersk-lib.buildPackage {
              pname = "ssh_ca_server-fuzz-smoke";
              src = fuzzSrc;
              buildInputs = common.buildInputs;
              LIBCLANG_PATH = common.LIBCLANG_PATH;
              doCheck = false;
              singleStep = true;
              RUSTC_BOOTSTRAP = "1";
            };
        };
      }
    );
}
