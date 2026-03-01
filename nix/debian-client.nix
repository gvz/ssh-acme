{ pkgs, lib }:
pkgs.stdenv.mkDerivation {
  pname = "ssh-ca-client-deb";
  version = "0.1.0";
  src = ./../clients;

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
}
