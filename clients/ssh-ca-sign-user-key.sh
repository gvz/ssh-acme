#!/usr/bin/env bash
#
# ssh-ca-sign-user-key.sh - Request a signed user certificate from an SSH CA server
#
# The user authenticates to the CA with their username and password (PAM),
# sends their SSH public key as channel data (stdin), and receives the signed
# certificate on stdout.
#
# Usage:
#   ssh-ca-sign-user-key.sh -s ca.example.com [OPTIONS]
#
# See --help for full option list.

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_PORT=2222
readonly DEFAULT_KEY="$HOME/.ssh/id_ed25519.pub"
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

Request a signed user certificate from an SSH Certificate Authority server.

The user authenticates with their username and password (PAM) over SSH.
The public key is sent as channel data (stdin) and the signed certificate
is received on stdout. You will be prompted for your password interactively.

Required:
  -s, --server <HOST>         CA server address (hostname or IP)

Options:
  -p, --port <PORT>           CA server SSH port (default: $DEFAULT_PORT)
  -u, --user <NAME>           Username for authentication (default: \$USER)
  -k, --key <PATH>            Path to SSH public key to be signed
                              (default: $DEFAULT_KEY)
  -o, --output <PATH>         Output certificate path
                              (default: <key_without_.pub>-cert.pub)
      --known-hosts <PATH>    Custom known_hosts file for the CA server
      --no-host-check         Disable strict host key checking for the CA
      --retry <N>             Number of retry attempts (default: $DEFAULT_RETRY_COUNT)
      --retry-delay <SEC>     Delay between retries in seconds (default: $DEFAULT_RETRY_DELAY)
  -v, --verbose               Enable verbose output
  -h, --help                  Show this help message

Examples:
  # Sign your default key (~/.ssh/id_ed25519.pub)
  $SCRIPT_NAME -s ca.example.com

  # Sign a specific key with a custom username
  $SCRIPT_NAME -s ca.example.com -u alice -k ~/.ssh/id_ed25519.pub

  # Use a custom port and output path
  $SCRIPT_NAME -s ca.example.com -p 2222 -o ~/.ssh/my-cert.pub

  # Retry up to 3 times with 10s delay
  $SCRIPT_NAME -s ca.example.com --retry 3 --retry-delay 10
EOF
}

# --- Argument Parsing -------------------------------------------------------

SERVER=""
PORT="$DEFAULT_PORT"
USERNAME="${USER:-}"
KEY="$DEFAULT_KEY"
OUTPUT=""
KNOWN_HOSTS=""
NO_HOST_CHECK="false"
RETRY_COUNT="$DEFAULT_RETRY_COUNT"
RETRY_DELAY="$DEFAULT_RETRY_DELAY"
VERBOSE="false"

parse_args() {
  local args
  args=$(getopt -o s:p:u:k:o:vh \
    --long server:,port:,user:,key:,output:,known-hosts:,no-host-check,retry:,retry-delay:,verbose,help \
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
    -u | --user)
      USERNAME="$2"
      shift 2
      ;;
    -k | --key)
      KEY="$2"
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

  if [[ -z "$USERNAME" ]]; then
    log_error "Username could not be determined. Set \$USER or use -u / --user"
    exit 1
  fi

  if [[ ! -f "$KEY" ]]; then
    log_error "Public key not found: $KEY"
    log_error "Generate one with: ssh-keygen -t ed25519"
    exit 1
  fi

  if [[ ! -r "$KEY" ]]; then
    log_error "Public key is not readable: $KEY"
    exit 1
  fi

  # Sanity check: the key file should look like a public key
  local key_content
  key_content="$(head -1 "$KEY")"
  if [[ "$key_content" != ssh-* ]] && [[ "$key_content" != ecdsa-* ]]; then
    log_error "File does not appear to be an SSH public key: $KEY"
    log_error "Expected file starting with 'ssh-' or 'ecdsa-', got: ${key_content:0:40}..."
    exit 1
  fi

  if [[ -z "$OUTPUT" ]]; then
    # Derive output path: ~/.ssh/id_ed25519.pub -> ~/.ssh/id_ed25519-cert.pub
    local key_base="${KEY%.pub}"
    if [[ "$key_base" == "$KEY" ]]; then
      # Key path didn't end in .pub, append -cert.pub
      OUTPUT="${KEY}-cert.pub"
    else
      OUTPUT="${key_base}-cert.pub"
    fi
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
    # Disable pseudo-terminal allocation; stdin/stdout carry data, not terminal
    -T
    -p "$PORT"
    # Disable escape characters so binary data passes through cleanly
    -o "EscapeChar=none"
    # Prefer keyboard-interactive/password auth, not public key
    -o "PreferredAuthentications=keyboard-interactive,password"
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

  cmd+=("${USERNAME}@${SERVER}")

  # Return as a properly quoted array representation
  printf '%q ' "${cmd[@]}"
}

# --- Execute Signing --------------------------------------------------------

sign_user_key() {
  local tmpfile
  tmpfile="$(mktemp "${OUTPUT}.XXXXXX")"
  # Ensure tmpfile is cleaned up on failure
  trap 'rm -f "$tmpfile"' EXIT

  local ssh_cmd
  ssh_cmd="$(build_ssh_cmd)"
  log_verbose "SSH command: $ssh_cmd < $KEY"

  local attempt=0
  local max_attempts=$((RETRY_COUNT + 1))

  while ((attempt < max_attempts)); do
    attempt=$((attempt + 1))

    if ((attempt > 1)); then
      log_info "Retry attempt $((attempt - 1))/$RETRY_COUNT (waiting ${RETRY_DELAY}s)..."
      sleep "$RETRY_DELAY"
    fi

    log_info "Requesting user certificate from $SERVER:$PORT as '$USERNAME' (attempt $attempt/$max_attempts)..."

    local exit_code=0
    # The password prompt is shown on stderr (the terminal).
    # stdin is redirected from the public key file.
    # stdout (the signed certificate) is captured to tmpfile.
    eval "$ssh_cmd" <"$KEY" >"$tmpfile" || exit_code=$?

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

      log_info "User certificate written to: $OUTPUT"

      # Verify the certificate
      if command -v ssh-keygen &>/dev/null; then
        log_info "Certificate details:"
        ssh-keygen -L -f "$OUTPUT" >&2 || true
      fi

      return 0
    fi

    log_error "SSH command failed with exit code $exit_code"
    if ((attempt < max_attempts)); then
      log_verbose "Will retry..."
    fi
  done

  log_error "All $max_attempts attempts failed"
  rm -f "$tmpfile"
  trap - EXIT
  exit 1
}

# --- Print Post-Signing Instructions ----------------------------------------

print_instructions() {
  log_info "User certificate signing complete."
  log_info ""
  log_info "The certificate will be used automatically if it is alongside"
  log_info "your private key, or you can configure ~/.ssh/config:"
  log_info "  Host *"
  log_info "      CertificateFile $OUTPUT"
  log_info "      IdentityFile    ${KEY%.pub}"
  log_info ""
  log_info "Verify with: ssh-keygen -L -f $OUTPUT"
}

# --- Main -------------------------------------------------------------------

main() {
  parse_args "$@"
  validate
  sign_user_key
  print_instructions
}

main "$@"
