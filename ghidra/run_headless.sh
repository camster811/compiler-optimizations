#!/usr/bin/env bash
# Run the Ghidra extraction over the 16 analysis artifacts (8 retained + 8 stripped).
#
# Writes
#   ghidra/output/<retained|stripped>/<sample_id>_<opt>.json   analyzer-facing record
#   ghidra/logs/<retained|stripped>/<sample_id>_<opt>.run.json PRIVATE run metadata
#   ghidra/logs/<retained|stripped>/<sample_id>_<opt>.log      PRIVATE headless log
#
# The oracle artifacts are never read. The only oracle value used is the function
# start address (analysis_region_start) from the private mapping, passed to the
# script so it can find the function; the region end is not passed. Each binary is
# imported as <sample_id>.elf so neither the optimization level nor the symbol
# condition appears in the Ghidra program name.
#
# Usage: ghidra/run_headless.sh [GHIDRA_HOME override via env: GHIDRA_HOME=...]

set -Eeuo pipefail

if (( $# )); then
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    exec python3 -m evaluation.corpus_pipeline extract "$@"
fi
umask 022

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT="$(dirname "$SCRIPT_DIR")"
readonly GHIDRA_HOME="${GHIDRA_HOME:-$SCRIPT_DIR/ghidra_12.1.4_PUBLIC}"
readonly CONFIG="$SCRIPT_DIR/config.json"
readonly MAPPING="$ROOT/evaluation/oracle_mapping.csv"
readonly OUT_DIR="$SCRIPT_DIR/output"
readonly LOG_DIR="$SCRIPT_DIR/logs"
readonly HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -x "$HEADLESS" ]] || die "analyzeHeadless not found at $HEADLESS (set GHIDRA_HOME)"

config_value() {
    python3 - "$CONFIG" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
PY
}

readonly EXPECTED_VERSION="$(config_value ghidra_version)"
readonly ANALYSIS_TIMEOUT="$(config_value analysis.analysis_timeout_per_file_s)"
grep -q "^application.version=$EXPECTED_VERSION\$" "$GHIDRA_HOME/Ghidra/application.properties" \
    || die "Ghidra at $GHIDRA_HOME is not version $EXPECTED_VERSION"

# sample_id, optimization, analysis_region_start: the only oracle columns read.
mapfile -t TARGETS < <(python3 - "$MAPPING" <<'PY'
import csv, sys
for row in csv.DictReader(open(sys.argv[1], newline="")):
    print(row["sample_id"], row["optimization"], row["analysis_region_start"])
PY
)
[[ ${#TARGETS[@]} -gt 0 ]] || die "no targets in $MAPPING"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

runs=0
for condition in retained stripped; do
    mkdir -p "$OUT_DIR/$condition" "$LOG_DIR/$condition"
    for target in "${TARGETS[@]}"; do
        read -r sample opt address <<<"$target"
        tag="${sample}_${opt}"
        binary="$ROOT/build/artifacts/$condition/$tag.elf"
        [[ -f "$binary" ]] || die "missing artifact $binary"

        record="$OUT_DIR/$condition/$tag.json"
        meta="$LOG_DIR/$condition/$tag.run.json"
        log="$LOG_DIR/$condition/$tag.log"
        rm -f "$record" "$meta" "$log"

        run_dir="$WORK/$condition/$tag"
        mkdir -p "$run_dir/project"
        cp "$binary" "$run_dir/$sample.elf"

        printf '[%s] %s ... ' "$condition" "$tag"
        "$HEADLESS" "$run_dir/project" extract \
            -import "$run_dir/$sample.elf" \
            -scriptPath "$SCRIPT_DIR/scripts" \
            -postScript ExtractRegion.java "$CONFIG" "$sample" "$address" "$record" "$meta" \
            -analysisTimeoutPerFile "$ANALYSIS_TIMEOUT" \
            -deleteProject >"$log" 2>&1 || die "analyzeHeadless failed; see $log"

        # Headless can exit 0 after a script error, so require the outputs.
        if grep -q 'SCRIPT ERROR' "$log" || [[ ! -s "$record" || ! -s "$meta" ]]; then
            die "extraction did not produce $record; see $log"
        fi
        echo ok
        runs=$((runs + 1))
    done
done

echo "extracted $runs records into $OUT_DIR"
