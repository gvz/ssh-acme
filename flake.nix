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

      in
      {
        # Replaces `defaultPackage` with the standard `packages.default`
        packages = {
          default = app;
          deb-client = deb-client;
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
              systemd
              pcsclite
              pam
              gnumake
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
        };
      }
    );
}
