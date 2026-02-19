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
          pname = "ssh_acme_server";
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
        sshAcmeServerModule =
          { config, ... }:
          {
            options.services.ssh-acme-server = {
              enable = lib.mkEnableOption "ssh-acme-server";

              configFile = lib.mkOption {
                type = lib.types.path;
                default = "/etc/ssh_acme_server/config.toml";
                description = "Path to the ssh-acme-server configuration file.";
              };

              dataDir = lib.mkOption {
                type = lib.types.path;
                default = "/var/lib/ssh-acme-server";
                description = "The data directory for the ssh-acme-server.";
              };
            };

            config = lib.mkIf config.services.ssh-acme-server.enable {
              # Create a dedicated user for the service

              systemd.services.ssh-acme-server = {
                description = "SSH ACME Server";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                serviceConfig = {
                  Environment = "RUST_LOG=debug";
                  ExecStart = ''
                    ${app}/bin/ssh_acme_server -c ${config.services.ssh-acme-server.configFile}
                  '';

                  Restart = "no";
                  # Creates /var/lib/ssh-acme-server with correct ownership
                  StateDirectory = "ssh-acme-server";
                };
              };
            };
          };
      in
      {
        # Replaces `defaultPackage` with the standard `packages.default`
        packages = {
          default = app;
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

        nixosModules.default = sshAcmeServerModule;

        checks = {
          cargo-tests = test_app;
          nixos-test = import ./tests/nixos_test/test.nix {
            inherit nixpkgs;
            sshAcmeServerModule = sshAcmeServerModule;
          };
        };
      }
    );
}
