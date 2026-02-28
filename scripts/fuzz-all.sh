#!/usr/bin/env bash
set -euo pipefail

# Run all fuzz targets in parallel for specified duration

DURATION="${1:-600}" # 10 minutes default
PARALLEL="${2:-yes}" # Run in parallel by default

echo "Running all fuzz targets for ${DURATION}s each"

if [ "$PARALLEL" = "yes" ]; then
  for target in $(cargo fuzz list); do
    echo "Starting $target in background..."
    ./scripts/run-fuzzing.sh "$target" "$DURATION" &
  done
  wait
else
  for target in $(cargo fuzz list); do
    echo "Running $target sequentially..."
    ./scripts/run-fuzzing.sh "$target" "$DURATION"
  done
fi

echo "All fuzzing jobs completed"
