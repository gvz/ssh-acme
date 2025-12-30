{ nixpkgs, sshAcmeServerModule }:
let pkgs = import nixpkgs { system = "x86_64-linux"; };
in pkgs.nixosTest {
  name = "ssh-acme-server-test";
  nodes.CA = {
    # Import the module passed from the flake
    imports = [ sshAcmeServerModule ];

    # Keep openssh for ssh-keygen
    environment.systemPackages = [ pkgs.openssh ];

    # Enable and configure the service
    services.ssh-acme-server = {
      enable = true;
      # Point the service to the config file copied by the test script
      configFile = "/etc/ssh_acme/config.toml";
    };
  };

  testScript = ''
    start_all()
    CA.wait_for_unit("multi-user.target")

    # Copy config from host to VM
    CA.copy_from_host("${./config}", "/etc/ssh_acme")

    # Generate CA key
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh_acme/ca_key -C CA_KEY -N \"\" ")
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -C ca_host_key -N \"\" ")
    CA.copy_from_vm("/etc/ssh_acme/ca_key.pub", "./ca_key.pub")

    # start service
    ret = CA.succeed("systemctl cat ssh-acme-server")
    print(ret)
    CA.execute("systemctl restart ssh-acme-server",False)
    ret = CA.succeed("journalctl -xeu ssh-acme-server.service")
    print(ret)

    CA.succeed("systemctl restart ssh-acme-server")
    CA.wait_for_unit("ssh-acme-server.service")

    # Verify that the service is indeed active
    CA.succeed("systemctl is-active ssh-acme-server.service")
  '';
}
