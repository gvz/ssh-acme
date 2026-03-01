#!/usr/bin/env bash
set -euo pipefail

# Run all fuzz targets for a specified duration

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run all fuzz targets for a specified duration.

Options:
    -d, --duration SECONDS   Fuzzing duration per target in seconds (default: 600)
    -p, --parallel yes|no    Run targets in parallel (default: yes)
    -j, --jobs N             Per-target parallel fuzzing jobs via libFuzzer
    -w, --workers N          Per-target parallel workers (defaults to jobs)
    -h, --help               Show this help message

Examples:
    $(basename "$0")                          # 10 min each, targets in parallel
    $(basename "$0") -d 3600                  # 1 hour each, targets in parallel
    $(basename "$0") -d 600 -p no             # 10 min each, targets sequentially
    $(basename "$0") -d 600 -j 4             # 10 min each, targets in parallel, 4 jobs per target
    $(basename "$0") -d 3600 -j 8 -w 4      # 1 hour, 8 jobs with 4 workers per target
EOF
  exit 0
}

DURATION="600"
PARALLEL="yes"
JOBS=""
WORKERS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  -d | --duration)
    DURATION="$2"
    shift 2
    ;;
  -p | --parallel)
    PARALLEL="$2"
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

# Build common arguments for run-fuzzing.sh
RUN_ARGS=(-d "$DURATION")
if [[ -n "$JOBS" ]]; then
  RUN_ARGS+=(-j "$JOBS")
fi
if [[ -n "$WORKERS" ]]; then
  RUN_ARGS+=(-w "$WORKERS")
fi

echo "Running all fuzz targets for ${DURATION}s each"
if [[ -n "$JOBS" ]]; then
  echo "Per-target parallelization: $JOBS jobs, ${WORKERS:-$JOBS} workers"
fi

# Collect targets
mapfile -t TARGETS < <(cargo fuzz list)

# Track results: parallel arrays of target names and their exit codes
declare -a TARGET_NAMES=()
declare -a TARGET_RESULTS=()

if [ "$PARALLEL" = "yes" ]; then
  declare -a PIDS=()
  for target in "${TARGETS[@]}"; do
    echo "Starting $target in background..."
    ./scripts/run-fuzzing.sh -t "$target" "${RUN_ARGS[@]}" &
    PIDS+=($!)
    TARGET_NAMES+=("$target")
  done
  # Wait for each PID individually to capture its exit code
  for i in "${!PIDS[@]}"; do
    set +e
    wait "${PIDS[$i]}"
    TARGET_RESULTS+=($?)
    set -e
  done
else
  for target in "${TARGETS[@]}"; do
    echo "Running $target sequentially..."
    set +e
    ./scripts/run-fuzzing.sh -t "$target" "${RUN_ARGS[@]}"
    TARGET_RESULTS+=($?)
    set -e
    TARGET_NAMES+=("$target")
  done
fi

# Print summary
echo ""
echo "=== Fuzzing Summary ==="

CRASHED=0
for i in "${!TARGET_NAMES[@]}"; do
  target="${TARGET_NAMES[$i]}"
  result="${TARGET_RESULTS[$i]}"
  if [[ "$result" -ne 0 ]]; then
    echo "  CRASH: $target -> see fuzz/artifacts/$target/"
    CRASHED=$((CRASHED + 1))
  else
    echo "     OK: $target"
  fi
done

echo ""
if [[ "$CRASHED" -gt 0 ]]; then
  echo "$CRASHED target(s) had crashes!"
  exit 1
else
  echo "All targets completed — no crashes detected."
  exit 0
fi
