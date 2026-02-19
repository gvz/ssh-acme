{ nixpkgs, sshAcmeServerModule }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  test_utils_lib = ./test_utils.py;
in
pkgs.testers.nixosTest {
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
      # open port 2222 in firewall
      networking.firewall.allowedTCPPorts = [ 2222 ];
      # Create test users, needed to authenticate via PAM
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
    };
    TmpHost = {
      environment.systemPackages = [ pkgs.openssh ];
    };
    TestHost = {
      # Keep openssh for ssh-keygen
      environment.systemPackages = [
        pkgs.openssh
        pkgs.sshpass
      ];
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
        hostKeys = [
          {
            path = "/tmp/TestHost_key";
            type = "ed25519";
          }
        ];
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
        alice = {
          isNormalUser = true;
        };
        bob = {
          isNormalUser = true;
        };
      };
    };
  };
  extraPythonPackages = p: [ p.jinja2 ];
  testScript = ''
    import sys
    import time
    # Link the external file into the current working directory of the driver
    # Or just add its directory to the path
    sys.path.append("${builtins.dirOf test_utils_lib}")

    from test_utils import generate_ca_key, prepare_Client, add_ca_to_knownhost, build_test_host_config # type: ignore

    start_all()
    CA.wait_for_unit("multi-user.target")
    TestHost.wait_for_unit("multi-user.target")
    Client.wait_for_unit("multi-user.target")

    # Copy config from host to VM
    CA.copy_from_host("${./config}", "/etc/ssh_acme")

    # Generate TestHost key
    TestHost.succeed("ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -C ca_host_key -N \"\" ")

    # Generate CA key
    generate_ca_key(CA)
    build_test_host_config(TestHost, CA)

    add_ca_to_knownhost(TestHost, CA)


    prepare_Client(Client, CA)


    TestHost.execute("systemctl stop sshd",False)

    print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    # start service
    CA.succeed("systemctl restart ssh-acme-server")
    CA.wait_for_unit("ssh-acme-server.service")

    # Verify that the service is indeed active
    CA.succeed("systemctl is-active ssh-acme-server.service")
    time.sleep(1)

    print("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    # TODO: add ca to known hosts on temp host
    test_key = CA.succeed("cat /etc/ssh_acme/hosts/testhost.toml")
    print(test_key)

    # Get TestHost's host key signed
    TestHost.succeed("ssh -i /etc/ssh/ssh_host_ed25519_key -p 2222 TestHost@CA > /tmp/TestHost.cert")
    print("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
    ret = TestHost.succeed("cat /tmp/TestHost.cert")
    print(ret)

  '';
}
