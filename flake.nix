{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };

      in {
        defaultPackage = naersk-lib.buildPackage {
          doCheck = false;
          release = true;
          cargoTestOptions = x: x ++ [ "--features test_auth" ];

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
        };
        devShell = with pkgs;
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
        checks = {
          nixos-test =
            import ./tests/nixos_test/test.nix { inherit self nixpkgs; };
        };
      });
}
