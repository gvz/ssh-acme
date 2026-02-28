#!/usr/bin/env bash
# End-to-end test for the SSH CA server using Docker containers.
# Mirrors the NixOS end-to-end test in tests/end_to_end_test/.
#
# Prerequisites: .deb packages must already be copied into docker/
# before building the images (the CI workflow handles this).
#
# Usage: bash docker/run_e2e_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DC="docker compose -f ${SCRIPT_DIR}/docker-compose.yml"

# Helpers to run commands inside containers
ca() { $DC exec -T ca "$@"; }
testhost() { $DC exec -T testhost "$@"; }
client() { $DC exec -T client "$@"; }

cleanup() {
  echo "=== Cleanup ==="
  ca cat /tmp/ca.log
  $DC down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Phase 1: Start containers ==="
$DC up -d --wait

echo "=== Phase 2: Setup CA config ==="
# Copy test configuration into the CA container, overwriting the
# default config that was baked in by the .deb package.
$DC cp "${SCRIPT_DIR}/test_config/config.toml" ca:/etc/ssh_ca_server/config.toml
$DC cp "${SCRIPT_DIR}/test_config/user.toml" ca:/etc/ssh_ca_server/user.toml
$DC cp "${SCRIPT_DIR}/test_config/user_default.toml" ca:/etc/ssh_ca_server/user_default.toml
$DC cp "${SCRIPT_DIR}/test_config/test_user_template.toml" ca:/etc/ssh_ca_server/test_user_template.toml
ca mkdir -p /etc/ssh_ca_server/hosts

# Create alice and bob users on the CA so PAM authentication works
ca useradd -m -s /bin/bash alice 2>/dev/null || true
ca bash -c 'echo "alice:alice" | chpasswd'
ca useradd -m -s /bin/bash bob 2>/dev/null || true
ca bash -c 'echo "bob:bob" | chpasswd'

echo "=== Phase 3: Generate CA keys ==="
# Remove the default keys that were generated at image build time
ca rm -f /etc/ssh_ca_server/ca_key /etc/ssh_ca_server/ca_key.pub \
  /etc/ssh_ca_server/ssh_ca_host_ed25519_key /etc/ssh_ca_server/ssh_ca_host_ed25519_key.pub \
  /etc/ssh_ca_server/ssh_ca_host_ed25519_key-cert.pub

# Generate fresh CA signing key
ca ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ca_key -C CA_KEY -N ""
# Generate fresh SSH host key for the CA server itself
ca ssh-keygen -t ed25519 -f /etc/ssh_ca_server/ssh_ca_host_ed25519_key -C ca_host_key -N ""
# Self-sign the CA server's host key so clients can verify it
ca ssh-keygen -s /etc/ssh_ca_server/ca_key -h -I CA -n ca -V +1d \
  /etc/ssh_ca_server/ssh_ca_host_ed25519_key.pub

echo "=== Phase 4: Build TestHost config for CA ==="
# Read TestHost's public key and create a host inventory entry on the CA
TESTHOST_PUBKEY=$(testhost cat /etc/ssh/ssh_host_ed25519_key.pub)
# Write the host config via the CA container to avoid quoting issues
ca bash -c "cat > /etc/ssh_ca_server/hosts/testhost.toml" <<EOF
validity_in_days = 365
hostnames = ["testhost"]
public_key = "${TESTHOST_PUBKEY}"
extensions = []
[critical_options]
EOF

echo "=== Phase 5: Distribute CA public key ==="
CA_PUBKEY=$(ca cat /etc/ssh_ca_server/ca_key.pub)

# Install the CA as a trusted cert-authority in known_hosts on client and testhost
for container in client testhost; do
  for user in alice bob root; do
    if [ "$user" = "root" ]; then
      homedir="/root"
    else
      homedir="/home/$user"
    fi
    $DC exec -T "$container" mkdir -p "${homedir}/.ssh"
    $DC exec -T "$container" bash -c "echo '@cert-authority * ${CA_PUBKEY}' > ${homedir}/.ssh/known_hosts"
    $DC exec -T "$container" chown -R "$user": "${homedir}/.ssh" 2>/dev/null || true
  done
done

echo "=== Phase 6: Generate client keys ==="
client su alice -c 'ssh-keygen -t ed25519 -f /home/alice/.ssh/id_ed25519 -N ""'
client su bob -c 'ssh-keygen -t ed25519 -f /home/bob/.ssh/id_ed25519 -N ""'

echo "=== Phase 7: Start CA server ==="
# Start the server in the background inside the container
ca find / -name ssh_ca_server
ca bash -c 'RUST_LOG=debug /usr/bin/ssh_ca_server -c /etc/ssh_ca_server/config.toml 2> /tmp/ca.log &'
ca echo TEST >> /tmp/ca.log
# Give the server a moment to bind to port 2222
sleep 2

echo "=== Phase 8: Sign host key ==="
# Copy the host-signing client script into testhost and execute it
$DC cp "${REPO_ROOT}/clients/ssh-ca-sign-host-key.sh" testhost:/tmp/ssh-ca-sign-host-key.sh
testhost chmod +x /tmp/ssh-ca-sign-host-key.sh
testhost /tmp/ssh-ca-sign-host-key.sh \
  -s ca -p 2222 \
  -i /etc/ssh/ssh_host_ed25519_key \
  -n testhost \
  -o /etc/ssh/ssh_host_ed25519_key-cert.pub \
  -v

echo "=== Phase 9: Sign user keys ==="
$DC cp "${REPO_ROOT}/clients/ssh-ca-sign-user-key.sh" client:/tmp/ssh-ca-sign-user-key.sh
client chmod +x /tmp/ssh-ca-sign-user-key.sh

echo "=== Phase 9.1: Sign alice keys ==="
client su alice -c \
  'sshpass -p alice /tmp/ssh-ca-sign-user-key.sh -s ca -p 2222 -u alice -k /home/alice/.ssh/id_ed25519.pub -o /home/alice/.ssh/id_ed25519-cert.pub -v'

echo "=== Phase 9.2: Sign bob keys ==="
client su bob -c \
  'sshpass -p bob /tmp/ssh-ca-sign-user-key.sh -s ca -p 2222 -u bob -k /home/bob/.ssh/id_ed25519.pub -o /home/bob/.ssh/id_ed25519-cert.pub -v'

echo "=== Phase 10: Verify certificates exist ==="
client test -s /home/alice/.ssh/id_ed25519-cert.pub
echo "  alice certificate: OK"
client test -s /home/bob/.ssh/id_ed25519-cert.pub
echo "  bob certificate: OK"

echo "=== Phase 11: Place CA pubkey on TestHost for TrustedUserCAKeys ==="
testhost bash -c "echo '${CA_PUBKEY}' > /etc/ssh/ca_key.pub"

echo "=== Phase 12: Start TestHost sshd ==="
testhost /usr/sbin/sshd
# Give sshd a moment to start
sleep 1

echo "=== Phase 13: End-to-end SSH login (positive tests) ==="
ALICE_RESULT=$(client su alice -c \
  'ssh -o StrictHostKeyChecking=accept-new -i /home/alice/.ssh/id_ed25519 alice@testhost whoami')
ALICE_RESULT=$(echo "$ALICE_RESULT" | tr -d '[:space:]')
if [ "$ALICE_RESULT" != "alice" ]; then
  echo "FAIL: Expected 'alice', got '${ALICE_RESULT}'"
  exit 1
fi
echo "  PASS: alice logged in successfully"

BOB_RESULT=$(client su bob -c \
  'ssh -o StrictHostKeyChecking=accept-new -i /home/bob/.ssh/id_ed25519 bob@testhost whoami')
BOB_RESULT=$(echo "$BOB_RESULT" | tr -d '[:space:]')
if [ "$BOB_RESULT" != "bob" ]; then
  echo "FAIL: Expected 'bob', got '${BOB_RESULT}'"
  exit 1
fi
echo "  PASS: bob logged in successfully"

echo "=== Phase 14: Negative test (principal enforcement) ==="
if client su bob -c \
  'ssh -o StrictHostKeyChecking=accept-new -i /home/bob/.ssh/id_ed25519 alice@testhost whoami' 2>/dev/null; then
  echo "FAIL: bob should NOT be able to log in as alice"
  exit 1
fi
echo "  PASS: bob correctly denied login as alice"

echo ""
echo "=== ALL TESTS PASSED ==="
