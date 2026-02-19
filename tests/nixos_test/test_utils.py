import os
import uuid
from jinja2 import Template



def generate_ca_key(CA):
    # create key for CA to sign keys
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh_acme/ca_key -C CA_KEY -N \"\" ")
    # create host key for CA server
    CA.succeed("ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -C ca_host_key -N \"\" ")
    # sign host key with CA key
    CA.succeed("ssh-keygen -s /etc/ssh_acme/ca_key -h -I CA -n ca,CA -V +1d /etc/ssh/ssh_host_ed25519_key.pub")
    CA.copy_from_vm("/etc/ssh_acme/ca_key.pub", "./ca_key.pub")

def prepare_Client(Client, CA):
    Client.succeed("su alice -c 'ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 -C alice_key -N \"\" '")
    Client.succeed("su bob -c 'ssh-keygen -t ed25519 -f /home/bob/.ssh/id_ed25519 -C alice_key -N \"\" '")
    Client.copy_from_vm("/home/alice/.ssh/id_ed25519.pub", "./alice.pub")
    Client.copy_from_vm("/home/bob/.ssh/id_ed25519.pub", "./bob.pub")
    copy_between_hosts(CA,"/etc/ssh_acme/ca_key.pub", Client,"/tmp/ca_key.pub")


def build_test_host_config(TestHost, CA):
    TestHost.succeed("chmod go-rwx /etc/ssh/ssh_host_ed25519_key.pub")
    key = TestHost.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub")
    template = CA.succeed("cat /etc/ssh_acme/hosts/testhost.toml.j2")
    host_config = Template(template).render(public_key=key)
    with open("testhost.toml","w+") as template_file:
      template_file.write(host_config)
      template_file.close()
    CA.succeed("rm /etc/ssh_acme/hosts/testhost.toml.j2")
    CA.copy_from_host("testhost.toml", "/etc/ssh_acme/hosts/testhost.toml")
    conf = CA.succeed("cat /etc/ssh_acme/hosts/testhost.toml")
    print(conf)

def add_ca_to_knownhost(TestHost, CA):
    pubkey = CA.succeed("cat /etc/ssh_acme/ca_key.pub")
    with open("ssh_known_host","w+") as known_host:
        known_host.write(f"@cert-authority * {pubkey}")
        known_host.close()
    TestHost.copy_from_host("ssh_known_host", "/home/bob/.ssh/known_hosts")
    TestHost.copy_from_host("ssh_known_host", "/home/alice/.ssh/known_hosts")
    TestHost.copy_from_host("ssh_known_host", "/root/.ssh/known_hosts")


def copy_between_hosts(src_host, src_path, dst_host, dst_path):
    tmp_path = os.path.join(os.getcwd(), uuid.uuid4().hex)
    src_host.wait_for_file(src_path)
    src_host.copy_from_vm(src_path, tmp_path)
    if not os.path.exists(tmp_path):
      raise Exception(f"Transfer failed: {tmp_path} was not created on the host!")
    dst_host.copy_from_host(tmp_path, dst_path)


