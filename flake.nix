{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      naersk,
      fenix,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = nixpkgs.lib;

        # Core packages: rust-toolchain, naersk-lib, common, app, test_app
        packages' = import ./nix/packages.nix {
          inherit
            pkgs
            fenix
            naersk
            system
            ;
        };
        inherit (packages')
          rust-toolchain
          naersk-lib
          common
          app
          test_app
          ;

        # NixOS module
        sshCaServerModule = import ./nix/nixos-module.nix { inherit lib app; };

        # Debian packages
        deb-client = import ./nix/debian-client.nix { inherit pkgs lib; };
        deb-server = import ./nix/debian-server.nix {
          inherit
            pkgs
            lib
            app
            system
            ;
        };

      in
      {
        packages = {
          default = app;
          inherit deb-client deb-server;
        };

        defaultPackage = app;

        nativeBuildInputs = with pkgs; [
          autoPatchelfHook
        ];

        devShell = import ./nix/devshell.nix { inherit pkgs rust-toolchain; };

        nixosModules.default = sshCaServerModule;

        checks = import ./nix/checks.nix {
          inherit
            pkgs
            nixpkgs
            naersk-lib
            common
            test_app
            sshCaServerModule
            ;
        };
      }
    );
}
