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
      # Keep openssh for ssh-keygen, sshpass for password-based SSH in tests
      environment.systemPackages = [
        pkgs.openssh
        pkgs.sshpass
      ];
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

    # Generate CA key
    generate_ca_key(CA)
    # Use the NixOS-generated host key at /tmp/TestHost_key (matches sshd hostKeys config)
    build_test_host_config(TestHost, CA, "/tmp/TestHost_key")

    add_ca_to_knownhost(TestHost, CA)


    prepare_Client(Client, CA)
    add_ca_to_knownhost(Client, CA)


    TestHost.execute("systemctl stop sshd",False)

    # start service
    CA.succeed("systemctl restart ssh-acme-server")
    CA.wait_for_unit("ssh-acme-server.service")

    # Verify that the service is indeed active
    CA.succeed("systemctl is-active ssh-acme-server.service")
    time.sleep(1)

    # TODO: add ca to known hosts on temp host
    test_key = CA.succeed("cat /etc/ssh_acme/hosts/testhost.toml")
    print(test_key)

    # Get TestHost's host key signed (using the NixOS-generated host key)
    TestHost.succeed("ssh -i /tmp/TestHost_key -p 2222 TestHost@CA \"sign_host_key\" > /tmp/TestHost.cert")
    ret = TestHost.succeed("cat /tmp/TestHost.cert")
    print(ret)

    # === User Certificate Signing ===
    # Alice gets her key signed by the CA using password auth.
    # ssh -T disables PTY allocation; stdin (the public key) is sent as channel
    # data, which the server's data() handler passes to user_key_signer.
    Client.succeed(
        "su alice -c '"
        "sshpass -p alice ssh -T -p 2222 alice@CA "
        "< /home/alice/.ssh/id_ed25519.pub "
        "> /home/alice/.ssh/id_ed25519-cert.pub"
        "'"
    )
    # Sign bob's key
    Client.succeed(
        "su bob -c '"
        "sshpass -p bob ssh -T -p 2222 bob@CA "
        "< /home/bob/.ssh/id_ed25519.pub "
        "> /home/bob/.ssh/id_ed25519-cert.pub"
        "'"
    )

    # Verify the certificate was created and is non-empty
    Client.succeed("test -s /home/bob/.ssh/id_ed25519-cert.pub")
    Client.succeed("test -s /home/alice/.ssh/id_ed25519-cert.pub")
    alice_cert = Client.succeed("cat /home/alice/.ssh/id_ed25519-cert.pub")
    print(f"Alice user certificate: {alice_cert}")

    # === End-to-End: Alice SSHs into TestHost with her signed certificate ===
    # Write the CA public key to TestHost for TrustedUserCAKeys.
    # We read the content and write it directly to avoid copy_between_hosts
    # creating a directory instead of a file.
    ca_pubkey = CA.succeed("cat /etc/ssh_acme/ca_key.pub").strip()
    TestHost.succeed(f"echo '{ca_pubkey}' > /tmp/ca_key.pub")

    # Sync TestHost and Client clocks to match CA, so that certificates
    # are not rejected as "not yet valid" due to VM clock skew.
    ca_time = CA.succeed("date -u '+%Y-%m-%d %H:%M:%S'").strip()
    TestHost.succeed(f"date -u -s '{ca_time}'")
    Client.succeed(f"date -u -s '{ca_time}'")

    # Restart TestHost sshd with the signed host certificate now in place
    TestHost.succeed("systemctl start sshd")
    TestHost.wait_for_unit("sshd.service")

    # Alice SSHs from Client to TestHost; certificate auth should succeed
    result = Client.succeed(
        "su alice -c 'ssh -i /home/alice/.ssh/id_ed25519 alice@TestHost whoami'"
    )
    assert result.strip() == "alice", f"Expected 'alice', got '{result.strip()}'"
    result = Client.succeed(
        "su bob -c 'ssh -i /home/bob/.ssh/id_ed25519 bob@TestHost whoami'"
    )
    assert result.strip() == "bob", f"Expected 'bob', got '{result.strip()}'"
    print("End-to-end test passed: alice and bob logged into TestHost via certificate auth")

    # test that bob can not login as alice
    result = Client.fail(
        "su bob -c 'ssh -i /home/bob/.ssh/id_ed25519 alice@TestHost whoami'"
    )
    print(result)

  '';
}
