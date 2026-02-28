#!/usr/bin/env bash
set -euo pipefail

# Continuous fuzzing script for local or CI use

TARGET="${1:-fuzz_ipc_messages}"
DURATION="${2:-3600}" # 1 hour default

echo "Running fuzzing for target: $TARGET"
echo "Duration: ${DURATION}s"

# Create corpus and artifacts directories
mkdir -p fuzz/corpus/"$TARGET"
mkdir -p fuzz/artifacts/"$TARGET"

# Run fuzzer
cargo fuzz run "$TARGET" \
  --release \
  -- \
  -max_total_time="$DURATION" \
  -timeout=10 \
  -rss_limit_mb=4096 \
  -artifact_prefix=fuzz/artifacts/"$TARGET"/ \
  -print_final_stats=1

echo "Fuzzing completed. Check fuzz/artifacts/$TARGET/ for any crashes."
