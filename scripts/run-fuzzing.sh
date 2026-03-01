#!/usr/bin/env bash
set -euo pipefail

# Continuous fuzzing script for local or CI use

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run a single fuzz target.

Options:
    -t, --target TARGET      Fuzz target name (default: fuzz_ipc_messages)
    -d, --duration SECONDS   Fuzzing duration in seconds (default: 3600)
    -j, --jobs N             Number of fuzzing jobs to run
    -w, --workers N          Number of parallel workers (defaults to jobs)
    -h, --help               Show this help message

Examples:
    $(basename "$0")
    $(basename "$0") -t fuzz_cert_signing -d 600
    $(basename "$0") -t fuzz_ipc_messages -d 3600 -j 4
    $(basename "$0") -t fuzz_ipc_messages -j 8 -w 4
EOF
  exit 0
}

TARGET="fuzz_ipc_messages"
DURATION="3600"
JOBS=""
WORKERS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  -t | --target)
    TARGET="$2"
    shift 2
    ;;
  -d | --duration)
    DURATION="$2"
    shift 2
    ;;
  -j | --jobs)
    JOBS="$2"
    shift 2
    ;;
  -w | --workers)
    WORKERS="$2"
    shift 2
    ;;
  -h | --help)
    usage
    ;;
  *)
    echo "Error: unknown option '$1'" >&2
    usage
    ;;
  esac
done

echo "Running fuzzing for target: $TARGET"
echo "Duration: ${DURATION}s"

# Create corpus and artifacts directories
mkdir -p fuzz/corpus/"$TARGET"
mkdir -p fuzz/artifacts/"$TARGET"

# Build libfuzzer arguments
FUZZER_ARGS=(
  -max_total_time="$DURATION"
  -timeout=10
  -rss_limit_mb=4096
  -artifact_prefix=fuzz/artifacts/"$TARGET"/
  -print_final_stats=1
)

if [[ -n "$JOBS" ]]; then
  FUZZER_ARGS+=(-jobs="$JOBS")
  # Default workers to jobs if not explicitly set
  if [[ -n "$WORKERS" ]]; then
    FUZZER_ARGS+=(-workers="$WORKERS")
  else
    FUZZER_ARGS+=(-workers="$JOBS")
  fi
  echo "Parallel jobs: $JOBS, workers: ${WORKERS:-$JOBS}"
fi

# Run fuzzer (don't exit on failure — we check for crashes below)
set +e
cargo fuzz run "$TARGET" \
  --release \
  -- \
  "${FUZZER_ARGS[@]}"
FUZZ_EXIT=$?
set -e

# Check for crash artifacts
ARTIFACT_DIR="fuzz/artifacts/$TARGET"
CRASH_COUNT=0
if [[ -d "$ARTIFACT_DIR" ]]; then
  CRASH_COUNT=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f | wc -l)
fi

if [[ "$CRASH_COUNT" -gt 0 ]]; then
  echo ""
  echo "CRASHES DETECTED for $TARGET ($CRASH_COUNT artifact(s))"
  echo "  Artifacts: $ARTIFACT_DIR/"
  ls -1 "$ARTIFACT_DIR"
  exit 1
elif [[ "$FUZZ_EXIT" -ne 0 ]]; then
  echo ""
  echo "WARNING: $TARGET exited with code $FUZZ_EXIT but no artifacts found"
  exit "$FUZZ_EXIT"
else
  echo "Fuzzing completed for $TARGET — no crashes detected."
  exit 0
fi
