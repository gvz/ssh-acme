#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [--html|--shell] [TARGET...]

Export fuzz coverage data as HTML report or shell summary.

Options:
    --html      Generate HTML coverage report
    --shell     Print coverage summary to the terminal
    -h, --help  Show this help message

Arguments:
    TARGET      One or more fuzz targets (default: all targets)

Examples:
    $(basename "$0") --html
    $(basename "$0") --shell fuzz_ipc_messages
    $(basename "$0") --html fuzz_ipc_messages fuzz_cert_signing
EOF
  exit "${1:-0}"
}

FORMAT=""
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
  --html)
    FORMAT="html"
    shift
    ;;
  --shell)
    FORMAT="shell"
    shift
    ;;
  -h | --help)
    usage 0
    ;;
  -*)
    echo "Error: unknown option '$1'" >&2
    usage 1
    ;;
  *)
    TARGETS+=("$1")
    shift
    ;;
  esac
done

if [[ -z "$FORMAT" ]]; then
  echo "Error: specify --html or --shell" >&2
  usage 1
fi

SYSROOT="$(rustc --print sysroot)"
LLVM_PROFDATA="$SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata"
LLVM_COV="$SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"

for tool in "$LLVM_PROFDATA" "$LLVM_COV"; do
  if [[ ! -x "$tool" ]]; then
    echo "Error: $(basename "$tool") not found at $tool" >&2
    echo "Make sure llvm-tools-preview is installed in your Rust toolchain." >&2
    exit 1
  fi
done

# Default to all targets if none specified
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  mapfile -t TARGETS < <(cargo fuzz list 2>/dev/null)
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "Error: no fuzz targets found" >&2
    exit 1
  fi
fi

COVERAGE_DIR="fuzz/coverage"
OUTPUT_DIR="$COVERAGE_DIR/report"

# Collect coverage for each target
PROFDATA_FILES=()
BINARIES=()

for target in "${TARGETS[@]}"; do
  echo "Collecting coverage for $target..."

  corpus_dir="fuzz/corpus/$target"
  if [[ ! -d "$corpus_dir" ]] || [[ -z "$(ls -A "$corpus_dir" 2>/dev/null)" ]]; then
    echo "Warning: no corpus found for $target at $corpus_dir, skipping" >&2
    continue
  fi

  cargo fuzz coverage "$target" 2>&1

  target_profdata="$COVERAGE_DIR/$target/coverage.profdata"
  if [[ ! -f "$target_profdata" ]]; then
    echo "Warning: no profdata generated for $target, skipping" >&2
    continue
  fi

  PROFDATA_FILES+=("$target_profdata")

  # Find the coverage-instrumented binary.
  # cargo fuzz coverage builds into a separate "coverage" directory under the
  # workspace target dir, NOT the fuzz/target dir used by cargo fuzz run.
  target_bin="target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/$target"
  if [[ ! -f "$target_bin" ]]; then
    echo "Warning: binary for $target not found at $target_bin, skipping" >&2
    continue
  fi

  BINARIES+=("$target_bin")
done

if [[ ${#PROFDATA_FILES[@]} -eq 0 ]]; then
  echo "Error: no coverage data collected" >&2
  exit 1
fi

if [[ ${#BINARIES[@]} -eq 0 ]]; then
  echo "Error: no coverage binaries found" >&2
  exit 1
fi

# Merge all profdata files
MERGED_PROFDATA="$COVERAGE_DIR/merged.profdata"
echo "Merging coverage data..."
"$LLVM_PROFDATA" merge -sparse "${PROFDATA_FILES[@]}" -o "$MERGED_PROFDATA"

# llvm-cov takes the first binary as a positional arg,
# additional binaries are passed with -object flags.
FIRST_BIN="${BINARIES[0]}"
EXTRA_OBJECT_ARGS=()
for bin in "${BINARIES[@]:1}"; do
  EXTRA_OBJECT_ARGS+=("-object" "$bin")
done

case "$FORMAT" in
html)
  mkdir -p "$OUTPUT_DIR"
  echo "Generating HTML report..."
  "$LLVM_COV" show "$FIRST_BIN" "${EXTRA_OBJECT_ARGS[@]}" \
    -instr-profile="$MERGED_PROFDATA" \
    -format=html \
    -output-dir="$OUTPUT_DIR" \
    -show-line-counts-or-regions \
    -show-instantiations=false \
    -Xdemangler=rustfilt \
    --ignore-filename-regex='\.cargo/registry|rustc|/nix/store' 2>/dev/null ||
    "$LLVM_COV" show "$FIRST_BIN" "${EXTRA_OBJECT_ARGS[@]}" \
      -instr-profile="$MERGED_PROFDATA" \
      -format=html \
      -output-dir="$OUTPUT_DIR" \
      -show-line-counts-or-regions \
      -show-instantiations=false \
      --ignore-filename-regex='\.cargo/registry|rustc|/nix/store'
  echo "HTML report written to $OUTPUT_DIR/index.html"
  ;;
shell)
  echo ""
  "$LLVM_COV" report "$FIRST_BIN" "${EXTRA_OBJECT_ARGS[@]}" \
    -instr-profile="$MERGED_PROFDATA" \
    --ignore-filename-regex='\.cargo/registry|rustc|/nix/store' 2>/dev/null ||
    "$LLVM_COV" report "$FIRST_BIN" "${EXTRA_OBJECT_ARGS[@]}" \
      -instr-profile="$MERGED_PROFDATA" \
      --ignore-filename-regex='\.cargo/registry|rustc|/nix/store'
  ;;
esac
