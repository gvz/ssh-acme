{ nixpkgs, sshAcmeServerModule }:
let pkgs = import nixpkgs { system = "x86_64-linux"; };
in pkgs.nixosTest {
  name = "ssh-acme-server-test";
  nodes = {
    CA = {
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
    TmpHost = { environment.systemPackages = [ pkgs.openssh ]; };
    TestHost = {
      # Keep openssh for ssh-keygen
      environment.systemPackages = [ pkgs.openssh ];
      users.users = {
        alice = {
          isNormalUser = true;
          password = "alice";
        };
        bob = {
          isNormalUser = true;
          password = "bob";
        };
      };
      services.openssh = {
        enable = true;
        openFirewall = true;
        settings = {
          KbdInteractiveAuthentication = false;
          PasswordAuthentication = false;
          PermitRootLogin = "no";
        };
        hostKeys = [{
          path = "/tmp/TestHost_key";
          type = "ed25519";
        }];
        extraConfig = ''
          TrustedUserCAKeys /tmp/ca_key.pub
          HostCertificate /tmp/TestHost.cert
        '';
      };
    };
    Client = {
      # Keep openssh for ssh-keygen
      environment.systemPackages = [ pkgs.openssh ];
      users.users = {
        alice = { isNormalUser = true; };
        bob = { isNormalUser = true; };
      };
    };
  };

  testScript = ''
    start_all()
    CA.wait_for_unit("multi-user.target")
    test-host.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")

    # Copy config from host to VM
    CA.copy_from_host("${./config}", "/etc/ssh_acme")

    # Generate CA key
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh_acme/ca_key -C CA_KEY -N \"\" ")
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -C ca_host_key -N \"\" ")
    CA.copy_from_vm("/etc/ssh_acme/ca_key.pub", "./ca_key.pub")

    # Generate TestHost key
    TmpHost.succeed("ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -C ca_host_key -N \"\" ")
    TmpHost.copy_from_vm("/etc/ssh/ssh_host_ed25519_key.pub", "./TestHost.pub")
    TmpHost.copy_from_vm("/etc/ssh/ssh_host_ed25519_key", "./TestHost_key")
    TestHost.copy_from_host("./TestHost.pub", "/tmp/TestHost_key.pub")
    TestHost.copy_from_host("./TestHost_key", "/tmp/TestHost_key")

    # Generate Client key
    Client.succeed("su -u alice -c 'ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 -C alice_key -N \"\" '")
    Client.succeed("su -u bob -c 'ssh-keygen -t ed25519 -f /home/bob/.ssh/id_ed25519 -C alice_key -N \"\" '")
    Client.copy_from_vm("/home/alice/.ssh/id_ed25519.pub", "./alice.pub")
    Client.copy_from_vm("/home/bob/.ssh/id_ed25519.pub", "./bob.pub")

    # Deploy CA public key
    TestHost.copy_from_host("./ca_key.pub", "/tmp/ca_key.pub")
    Client.copy_from_host("./ca_key.pub", "/tmp/ca_key.pub")

    TestHost.execute("systemctl restart sshd",False)

    #TODO: build configs from jinja templates


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

    TmpHost.succeed("ssh -i /etc/ssh/ssh_host_ed25519_key.pub TestHost@CA sign_host_key > /tmp/TestHost.cert")

    TmpHost.copy_from_vm("/tmp/TestHost.cert", "./TestHost.cert")
  '';
}
