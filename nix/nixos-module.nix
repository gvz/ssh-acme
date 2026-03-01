{ lib, app }:
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
        StateDirectory = "ssh-ca-server";
      };
    };
  };
}
