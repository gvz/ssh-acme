#!/usr/bin/env bash
#
# ssh-ca-sign-host-key.sh - Request a signed host certificate from an SSH CA server
#
# The host authenticates to the CA using its host private key (public key auth)
# and executes the "sign_host_key" command. The signed certificate is returned
# on stdout and written to the output file.
#
# Usage:
#   ssh-ca-sign-host-key.sh -s ca.example.com [OPTIONS]
#
# See --help for full option list.

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_PORT=2222
readonly DEFAULT_HOST_KEY="/etc/ssh/ssh_host_ed25519_key"
readonly DEFAULT_RETRY_COUNT=0
readonly DEFAULT_RETRY_DELAY=5

# --- Logging ---------------------------------------------------------------

log_info() {
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [INFO]  $*" >&2
}

log_error() {
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [ERROR] $*" >&2
}

log_verbose() {
  if [[ "$VERBOSE" == "true" ]]; then
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [DEBUG] $*" >&2
  fi
}

# --- Usage / Help -----------------------------------------------------------

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME -s <CA_SERVER> [OPTIONS]

Request a signed host certificate from an SSH Certificate Authority server.

The host authenticates with its private key via SSH public key authentication
and runs the "sign_host_key" command on the CA server. The signed certificate
is written to the output file.

Required:
  -s, --server <HOST>         CA server address (hostname or IP)

Options:
  -p, --port <PORT>           CA server SSH port (default: $DEFAULT_PORT)
  -i, --identity <PATH>       Host private key path
                              (default: $DEFAULT_HOST_KEY)
  -n, --hostname <NAME>       Hostname to authenticate as (default: \$(hostname))
  -o, --output <PATH>         Output certificate path
                              (default: <identity>-cert.pub)
      --known-hosts <PATH>    Custom known_hosts file for the CA server
      --no-host-check         Disable strict host key checking for the CA
      --reload                Reload sshd after successful signing
      --retry <N>             Number of retry attempts (default: $DEFAULT_RETRY_COUNT)
      --retry-delay <SEC>     Delay between retries in seconds (default: $DEFAULT_RETRY_DELAY)
  -v, --verbose               Enable verbose output
  -h, --help                  Show this help message

Examples:
  # Sign the default host key using the CA at ca.example.com
  sudo $SCRIPT_NAME -s ca.example.com

  # Sign a specific key, custom port, and reload sshd after
  sudo $SCRIPT_NAME -s ca.example.com -p 2222 -i /etc/ssh/ssh_host_ed25519_key --reload

  # Use a custom known_hosts file for the CA and retry up to 3 times
  sudo $SCRIPT_NAME -s ca.example.com --known-hosts /etc/ssh_ca/ca_known_hosts --retry 3
EOF
}

# --- Argument Parsing -------------------------------------------------------

SERVER=""
PORT="$DEFAULT_PORT"
IDENTITY="$DEFAULT_HOST_KEY"
HOSTNAME=""
OUTPUT=""
KNOWN_HOSTS=""
NO_HOST_CHECK="false"
RELOAD="false"
RETRY_COUNT="$DEFAULT_RETRY_COUNT"
RETRY_DELAY="$DEFAULT_RETRY_DELAY"
VERBOSE="false"

parse_args() {
  local args
  args=$(getopt -o s:p:i:n:o:vh \
    --long server:,port:,identity:,hostname:,output:,known-hosts:,no-host-check,reload,retry:,retry-delay:,verbose,help \
    -n "$SCRIPT_NAME" -- "$@") || {
    usage
    exit 1
  }
  eval set -- "$args"

  while true; do
    case "$1" in
    -s | --server)
      SERVER="$2"
      shift 2
      ;;
    -p | --port)
      PORT="$2"
      shift 2
      ;;
    -i | --identity)
      IDENTITY="$2"
      shift 2
      ;;
    -n | --hostname)
      HOSTNAME="$2"
      shift 2
      ;;
    -o | --output)
      OUTPUT="$2"
      shift 2
      ;;
    --known-hosts)
      KNOWN_HOSTS="$2"
      shift 2
      ;;
    --no-host-check)
      NO_HOST_CHECK="true"
      shift
      ;;
    --reload)
      RELOAD="true"
      shift
      ;;
    --retry)
      RETRY_COUNT="$2"
      shift 2
      ;;
    --retry-delay)
      RETRY_DELAY="$2"
      shift 2
      ;;
    -v | --verbose)
      VERBOSE="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      log_error "Unexpected option: $1"
      usage
      exit 1
      ;;
    esac
  done
}

# --- Validation -------------------------------------------------------------

validate() {
  if [[ -z "$SERVER" ]]; then
    log_error "CA server address is required (-s / --server)"
    usage
    exit 1
  fi

  if [[ ! -f "$IDENTITY" ]]; then
    log_error "Host private key not found: $IDENTITY"
    exit 1
  fi

  if [[ ! -r "$IDENTITY" ]]; then
    log_error "Host private key is not readable: $IDENTITY (try running as root)"
    exit 1
  fi

  if [[ -z "$HOSTNAME" ]]; then
    HOSTNAME="$(hostname)"
    log_verbose "Using system hostname: $HOSTNAME"
  fi

  if [[ -z "$OUTPUT" ]]; then
    OUTPUT="${IDENTITY}-cert.pub"
    log_verbose "Using default output path: $OUTPUT"
  fi

  if [[ -n "$KNOWN_HOSTS" && ! -f "$KNOWN_HOSTS" ]]; then
    log_error "Known hosts file not found: $KNOWN_HOSTS"
    exit 1
  fi

  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
    log_error "Invalid port number: $PORT"
    exit 1
  fi

  if ! [[ "$RETRY_COUNT" =~ ^[0-9]+$ ]]; then
    log_error "Invalid retry count: $RETRY_COUNT"
    exit 1
  fi

  if ! [[ "$RETRY_DELAY" =~ ^[0-9]+$ ]]; then
    log_error "Invalid retry delay: $RETRY_DELAY"
    exit 1
  fi
}

# --- Build SSH Command ------------------------------------------------------

build_ssh_cmd() {
  local cmd=(
    ssh
    -i "$IDENTITY"
    -p "$PORT"
    # Disable stdin reading (we don't send channel data for host signing)
    -n
    # Disable pseudo-terminal allocation
    -T
    # Don't execute remote command via shell, prevent rc file execution
    -o "RequestTTY=no"
    # Prevent ssh from reading user config that might interfere
    -o "BatchMode=yes"
  )

  if [[ "$NO_HOST_CHECK" == "true" ]]; then
    cmd+=(-o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null")
    log_verbose "Host key checking disabled"
  fi

  if [[ -n "$KNOWN_HOSTS" ]]; then
    cmd+=(-o "UserKnownHostsFile=$KNOWN_HOSTS")
    log_verbose "Using known_hosts file: $KNOWN_HOSTS"
  fi

  if [[ "$VERBOSE" == "true" ]]; then
    cmd+=(-v)
  fi

  cmd+=("${HOSTNAME}@${SERVER}" "sign_host_key")

  printf '%q ' "${cmd[@]}"
}

# --- Execute Signing --------------------------------------------------------

sign_host_key() {
  local tmpfile
  tmpfile="$(mktemp "${OUTPUT}.XXXXXX")"
  # Ensure tmpfile is cleaned up on failure
  trap 'rm -f "$tmpfile"' EXIT

  local ssh_cmd
  ssh_cmd="$(build_ssh_cmd)"
  log_verbose "SSH command: $ssh_cmd"

  local attempt=0
  local max_attempts=$((RETRY_COUNT + 1))

  while ((attempt < max_attempts)); do
    attempt=$((attempt + 1))

    if ((attempt > 1)); then
      log_info "Retry attempt $((attempt - 1))/$RETRY_COUNT (waiting ${RETRY_DELAY}s)..."
      sleep "$RETRY_DELAY"
    fi

    log_info "Requesting host certificate from $SERVER:$PORT (attempt $attempt/$max_attempts)..."

    local exit_code=0
    eval "$ssh_cmd" >"$tmpfile" || exit_code=$?

    if ((exit_code == 0)); then
      # Validate the output looks like a certificate
      if [[ ! -s "$tmpfile" ]]; then
        log_error "CA returned empty response"
        if ((attempt < max_attempts)); then
          continue
        fi
        rm -f "$tmpfile"
        trap - EXIT
        exit 1
      fi

      # Check that the output starts with an SSH certificate marker
      local first_line
      first_line="$(head -1 "$tmpfile")"
      if [[ "$first_line" != *"-cert-"* ]] && [[ "$first_line" != ssh-* ]]; then
        log_error "CA response does not appear to be a valid certificate"
        log_error "Response starts with: $(head -c 100 "$tmpfile")"
        if ((attempt < max_attempts)); then
          continue
        fi
        rm -f "$tmpfile"
        trap - EXIT
        exit 1
      fi

      # Move certificate to final output path (atomic on same filesystem)
      mv -f "$tmpfile" "$OUTPUT"
      trap - EXIT

      log_info "Host certificate written to: $OUTPUT"

      # Verify the certificate
      if command -v ssh-keygen &>/dev/null; then
        log_info "Certificate details:"
        ssh-keygen -L -f "$OUTPUT" >&2 || true
      fi

      return 0
    fi

    log_error "SSH command failed with exit code $exit_code"
    if ((attempt < max_attempts)); then
      log_verbose "stderr output: $(cat "$tmpfile")"
    fi
  done

  log_error "All $max_attempts attempts failed"
  rm -f "$tmpfile"
  trap - EXIT
  exit 1
}

# --- sshd Reload ------------------------------------------------------------

reload_sshd() {
  if [[ "$RELOAD" != "true" ]]; then
    return 0
  fi

  log_info "Reloading sshd to pick up the new host certificate..."

  if command -v systemctl &>/dev/null; then
    if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; then
      log_info "sshd reloaded successfully"
    else
      log_error "Failed to reload sshd via systemctl"
      log_error "You may need to manually reload sshd:"
      log_error "  systemctl reload sshd"
      exit 1
    fi
  elif command -v service &>/dev/null; then
    if service sshd reload 2>/dev/null || service ssh reload 2>/dev/null; then
      log_info "sshd reloaded successfully"
    else
      log_error "Failed to reload sshd via service command"
      exit 1
    fi
  else
    log_error "Cannot find systemctl or service command to reload sshd"
    log_error "Please reload sshd manually"
    exit 1
  fi
}

# --- Print Post-Signing Instructions ----------------------------------------

print_instructions() {
  log_info "Host certificate signing complete."
  log_info ""
  log_info "Ensure your sshd_config contains:"
  log_info "  HostKey         $IDENTITY"
  log_info "  HostCertificate $OUTPUT"

  if [[ "$RELOAD" != "true" ]]; then
    log_info ""
    log_info "Then reload sshd:"
    log_info "  systemctl reload sshd"
  fi
}

# --- Main -------------------------------------------------------------------

main() {
  parse_args "$@"
  validate
  sign_host_key
  reload_sshd
  print_instructions
}

main "$@"
