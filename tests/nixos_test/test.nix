{ self, nixpkgs }:
let pkgs = import nixpkgs { system = "x86_64-linux"; };
in pkgs.nixosTest {
  name = "ssh-acme-server-test";
  nodes.CA = {
    environment.systemPackages =
      [ self.defaultPackage."x86_64-linux" pkgs.openssh ];
  };

  testScript = ''
    start_all()
    CA.wait_for_unit("multi-user.target")

    #copy config
    CA.copy_from_host("${./config}", "/etc/ssh_acme")
    ret = CA.succeed("ls -l /etc/systemd/system/")
    print(ret)

    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh_acme/ca_key -C CA_KEY -N \"\" ")
    CA.copy_from_vm("/etc/ssh_acme/ca_key.pub", "./ca_key.pub")

    CA.succeed("systemctl daemon-reload")
    # start server
    CA.succeed("systemctl start ssh_acme")
    CA.wait_for_unit("ssh_acme","root", 10)
  '';
}
