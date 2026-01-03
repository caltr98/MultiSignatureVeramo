#!/bin/bash

set -euo pipefail

# Usage: ./benchmark.sh start_issuers end_issuers
# Example: ./benchmark.sh 2 32  # runs with 2,4,8,16,32 issuers
#
# By default, the script stops once it would exceed 32 issuers.
# Override with MAX_ISSUERS (e.g. MAX_ISSUERS=64 ./benchmark.sh 2 32).
# Set DEBUG=1 for shell tracing; set DRY_RUN=1 to only print commands.
# Set SKIP_BUILD=1 to skip the initial TypeScript compilation step.
#
# Defaults:
# - CLAIMS_LIST="16 128"
# - SIZE=64
# - RUNS=30 (multisig + no-multisig)
# - EIP712_RUNS=30 (EIP712 benchmark, no sample VC printing)
# - RESUME=0 (set RESUME=1 to skip issuer rows already present in the output CSVs)
# - PRUNE=0 (set PRUNE=1 to delete existing rows for the issuer before re-running)
# - RUN_MULTISIG=1 / RUN_STANDARD=1 / RUN_EIP712=1 (set to 0 to skip a suite)

if [[ "${DEBUG:-0}" == "1" ]]; then
  set -x
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

start_issuers="${1-}"
end_issuers="${2-}"
MAX_ISSUERS="${MAX_ISSUERS:-32}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
CLAIMS_LIST="${CLAIMS_LIST:-16 128}"
SIZE="${SIZE:-64}"
RUNS="${RUNS:-30}"
EIP712_RUNS="${EIP712_RUNS:-30}"
RESUME="${RESUME:-0}"
PRUNE="${PRUNE:-0}"
RUN_MULTISIG="${RUN_MULTISIG:-1}"
RUN_STANDARD="${RUN_STANDARD:-1}"
RUN_EIP712="${RUN_EIP712:-1}"

if [[ -z "$start_issuers" || -z "$end_issuers" ]]; then
  echo "Usage: $0 <start_issuers> <end_issuers>"
  exit 1
fi

if [[ ! "$start_issuers" =~ ^[0-9]+$ || ! "$end_issuers" =~ ^[0-9]+$ ]]; then
  echo "Error: issuer counts must be non-negative integers."
  exit 1
fi

if [[ "$start_issuers" -lt 1 || "$end_issuers" -lt 1 ]]; then
  echo "Error: issuer counts must be >= 1."
  exit 1
fi

if [[ "$end_issuers" -lt "$start_issuers" ]]; then
  echo "Error: end_issuers must be >= start_issuers."
  exit 1
fi

if [[ ! "$MAX_ISSUERS" =~ ^[0-9]+$ || "$MAX_ISSUERS" -lt 1 ]]; then
  echo "Error: MAX_ISSUERS must be a positive integer."
  exit 1
fi

if [[ ! "$SIZE" =~ ^[0-9]+$ || "$SIZE" -lt 1 ]]; then
  echo "Error: SIZE must be a positive integer."
  exit 1
fi

if [[ ! "$RUNS" =~ ^[0-9]+$ || "$RUNS" -lt 1 ]]; then
  echo "Error: RUNS must be a positive integer."
  exit 1
fi

if [[ ! "$EIP712_RUNS" =~ ^[0-9]+$ || "$EIP712_RUNS" -lt 1 ]]; then
  echo "Error: EIP712_RUNS must be a positive integer."
  exit 1
fi

run_cmd() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

csv_has_issuer() {
  local csv_file="$1"
  local issuer="$2"
  [[ -f "$csv_file" ]] || return 1
  awk -F, -v issuer="$issuer" 'NR>1 && $1==issuer {found=1; exit} END{exit !found}' "$csv_file"
}

csv_prune_issuer() {
  local csv_file="$1"
  local issuer="$2"
  [[ -f "$csv_file" ]] || return 0
  local tmp="${csv_file}.tmp.$$"
  awk -F, -v issuer="$issuer" 'NR==1 || $1!=issuer {print}' "$csv_file" > "$tmp"
  mv "$tmp" "$csv_file"
}

maybe_run() {
  local csv_file="$1"
  local issuer="$2"
  local label="$3"
  shift 3
  if [[ "$RESUME" == "1" ]] && csv_has_issuer "$csv_file" "$issuer"; then
    echo "  skip $label (already in $(basename "$csv_file"))"
    return 0
  fi
  if [[ "$PRUNE" == "1" && "$DRY_RUN" != "1" ]]; then
    csv_prune_issuer "$csv_file" "$issuer"
  fi
  run_cmd "$@"
}

if [[ "$SKIP_BUILD" != "1" ]]; then
  run_cmd yarn tsc -p tsconfig.json
fi

for (( issuers=start_issuers; issuers<=end_issuers; issuers*=2 ))
do
  if (( issuers > MAX_ISSUERS )); then
    echo "Stopping: next run would use $issuers issuers (> MAX_ISSUERS=$MAX_ISSUERS)"
    break
  fi
  echo "Running benchmarks with $issuers issuers..."
  for claims in $CLAIMS_LIST; do
    echo "  claims=$claims size=$SIZE"

    if [[ "$RUN_MULTISIG" == "1" ]]; then
      echo "  multisig (sizes)"
      maybe_run "./experimental_results/message_sizes_claims${claims}_size${SIZE}.csv" "$issuers" "multisig sizes" \
        node ./src/test/full_sizes_test_main.js --claims "$claims" --size "$SIZE" --issuers "$issuers"

      echo "  multisig (benchmark)"
      maybe_run "./experimental_results/benchmark_results_claims${claims}_size${SIZE}.csv" "$issuers" "multisig benchmark" \
        node ./src/test/full_test_main.js --claims "$claims" --size "$SIZE" --issuers "$issuers" --runs "$RUNS"
    fi

    if [[ "$RUN_STANDARD" == "1" ]]; then
      echo "  no-multisig (sizes)"
      maybe_run "./experimental_results/message_sizes_standard_claims${claims}_size${SIZE}.csv" "$issuers" "no-multisig sizes" \
        node ./src/test_no_multisign/full_sizes_standard_test_main.js --claims "$claims" --size "$SIZE" --issuers "$issuers"

      echo "  no-multisig (benchmark)"
      maybe_run "./experimental_results/benchmark_standard_claims${claims}_size${SIZE}.csv" "$issuers" "no-multisig benchmark" \
        node ./src/test_no_multisign/full_test_standard_veramo.js --claims "$claims" --size "$SIZE" --issuers "$issuers" --runs "$RUNS"
    fi

    if [[ "$RUN_EIP712" == "1" ]]; then
      echo "  no-multisig EIP712 (benchmark)"
      maybe_run "./experimental_results/benchmark_standard_eip712_claims${claims}_size${SIZE}.csv" "$issuers" "no-multisig EIP712 benchmark" \
        node ./src/test_no_multisign_eip712/full_test_standard_veramo_eip712.js --claims "$claims" --size "$SIZE" --issuers "$issuers" --runs "$EIP712_RUNS" --printSample 0 --logRuns 0

      echo "  no-multisig EIP712 (sizes)"
      maybe_run "./experimental_results/message_sizes_standard_eip712_claims${claims}_size${SIZE}.csv" "$issuers" "no-multisig EIP712 sizes" \
        node ./src/test_no_multisign_eip712/full_sizes_standard_test_main_eip712.js --claims "$claims" --size "$SIZE" --issuers "$issuers"
    fi

  done
  echo "Done with $issuers issuers"
done
