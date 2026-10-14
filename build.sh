#!/usr/bin/env bash
# Build the pilot corpus from one compilation per source/optimization pair.
#
# Outputs (all derived from the same master ELF):
#   artifacts/oracle/    DWARF + normal symbols; evaluation use only
#   artifacts/retained/  DWARF removed; normal symbols retained
#   artifacts/stripped/  DWARF and removable symbols removed
#   artifacts/private/   source mapping, logs, hashes, and environment metadata

set -Eeuo pipefail

# Explicit arguments select the manifest-driven dataset builder. The no-argument
# legacy pilot path remains byte-for-byte equivalent below.
if (( $# )); then
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    exec python3 -m evaluation.corpus_pipeline build "$@"
fi
umask 022

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

readonly CC="${CC:-gcc-15}"
readonly OBJCOPY="${OBJCOPY:-objcopy}"
readonly STRIP="${STRIP:-strip}"
readonly READELF="${READELF:-readelf}"
readonly STRINGS="${STRINGS:-strings}"
readonly SHA256SUM="${SHA256SUM:-sha256sum}"

readonly EXPECTED_GCC_VERSION="${EXPECTED_GCC_VERSION:-15.2.0}"
readonly EXPECTED_BINUTILS_VERSION="${EXPECTED_BINUTILS_VERSION:-2.46}"

readonly ARTIFACT_ROOT="$SCRIPT_DIR/build/artifacts"
readonly ORACLE_DIR="$ARTIFACT_ROOT/oracle"
readonly RETAINED_DIR="$ARTIFACT_ROOT/retained"
readonly STRIPPED_DIR="$ARTIFACT_ROOT/stripped"
readonly PRIVATE_DIR="$ARTIFACT_ROOT/private"
readonly STAGED_SOURCE_DIR="$PRIVATE_DIR/staged_sources"
readonly LOG_DIR="$PRIVATE_DIR/logs"
readonly MANIFEST="$PRIVATE_DIR/build_manifest.tsv"
readonly ENVIRONMENT_FILE="$PRIVATE_DIR/environment.txt"

# Pilot conditions. Extend these arrays to O1/O3 only after the vertical slice
# passes artifact, leakage, oracle-mapping, and Ghidra validation.
readonly -a OPT_TAGS=(O0 O2)
readonly -a OPT_FLAGS=(-O0 -O2)

# Opaque analysis IDs map to ground truth only in the private manifest.
readonly -a SAMPLE_IDS=(sample_0001 sample_0002 sample_0003 sample_0004)
readonly -a SOURCE_PATHS=(
    source/vulnerable/case_s001.c
    source/fixed/case_s001.c
    source/vulnerable/case_h001.c
    source/fixed/case_h001.c
)
readonly -a PAIR_IDS=(pair_0001 pair_0001 pair_0002 pair_0002)
readonly -a CWES=(CWE-121 CWE-121 CWE-122 CWE-122)
readonly -a LABELS=(vulnerable fixed vulnerable fixed)
readonly -a ALLOCATIONS=(stack stack heap heap)

# Hardening is deliberately disabled because it is not an experimental factor.
# PIE is also disabled explicitly so address behavior does not depend on Ubuntu's
# distribution defaults. Do not add -fno-builtin: transformed memory operations
# are part of the phenomenon being measured.
readonly -a COMMON_CFLAGS=(
    -std=c11
    -Wall
    -Wextra
    -g
    -gdwarf-5
    -fno-stack-protector
    -U_FORTIFY_SOURCE
    -D_FORTIFY_SOURCE=0
    -fcf-protection=none
    -fno-pie
    "-fdebug-prefix-map=$SCRIPT_DIR=/experiment"
    "-ffile-prefix-map=$SCRIPT_DIR=/experiment"
)
readonly -a COMMON_LDFLAGS=(
    -no-pie
    -Wl,-z,noexecstack
)

readonly LEAK_PATTERN='CWE-?12[12]|Juliet|source/(vulnerable|fixed)|(^|[^[:alnum:]])(vulnerable|fixed|good|bad)([^[:alnum:]]|$)'

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

section_exists() {
    local artifact="$1"
    local section="$2"
    "$READELF" -W -S "$artifact" | grep -F "] $section " >/dev/null
}

has_debug_sections() {
    local artifact="$1"
    "$READELF" -W -S "$artifact" | grep -E '\.(z?debug_|gdb_index)' >/dev/null
}

has_executable_stack() {
    local artifact="$1"
    "$READELF" -W -l "$artifact" | grep -E 'GNU_STACK.*RWE' >/dev/null
}

text_hash() {
    local artifact="$1"
    local extracted="$TMP_DIR/text.bin"

    "$OBJCOPY" --only-section=.text -O binary "$artifact" "$extracted"
    [[ -s "$extracted" ]] || die "empty or missing .text section: $artifact"
    "$SHA256SUM" "$extracted" | awk '{print $1}'
}

check_leakage() {
    local artifact="$1"
    local matches

    matches="$($STRINGS -a "$artifact" | grep -Ein "$LEAK_PATTERN" || true)"
    if [[ -n "$matches" ]]; then
        {
            printf 'Artifact: %s\n' "$artifact"
            printf '%s\n\n' "$matches"
        } >> "$PRIVATE_DIR/leakage_failures.txt"
        return 1
    fi
}

for tool in "$CC" "$OBJCOPY" "$STRIP" "$READELF" "$STRINGS" "$SHA256SUM" awk grep sed cp mkdir nm; do
    require_tool "$tool"
done

actual_gcc_version="$($CC -dumpfullversion -dumpversion)"
[[ "$actual_gcc_version" == "$EXPECTED_GCC_VERSION" ]] ||
    die "expected GCC $EXPECTED_GCC_VERSION, found $actual_gcc_version via $CC"

actual_binutils_version="$($OBJCOPY --version | sed -n '1{s/.* //;p;}')"
[[ "$actual_binutils_version" == "$EXPECTED_BINUTILS_VERSION" ]] ||
    die "expected binutils $EXPECTED_BINUTILS_VERSION, found $actual_binutils_version"

fortify_value="$($CC "${COMMON_CFLAGS[@]}" -dM -E -x c /dev/null | awk '$2 == "_FORTIFY_SOURCE" {print $3}')"
[[ "${fortify_value:-0}" == "0" ]] ||
    die "_FORTIFY_SOURCE is still enabled at level $fortify_value"

mkdir -p "$ORACLE_DIR" "$RETAINED_DIR" "$STRIPPED_DIR" \
    "$STAGED_SOURCE_DIR" "$LOG_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

: > "$PRIVATE_DIR/leakage_failures.txt"

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    sample_id pair_id cwe ground_truth allocation optimization source_path \
    gcc_version binutils_version compile_flags oracle_path retained_path \
    stripped_path oracle_text_sha256 retained_text_sha256 stripped_text_sha256 \
    validation_passed > "$MANIFEST"

{
    printf 'os_release='; . /etc/os-release; printf '%s\n' "$PRETTY_NAME"
    printf 'kernel=%s\n' "$(uname -srmo)"
    printf 'gcc=%s\n' "$($CC --version | sed -n '1p')"
    printf 'binutils=%s\n' "$($OBJCOPY --version | sed -n '1p')"
    printf 'python=%s\n' "$(python3 --version 2>&1 || true)"
    printf 'java=%s\n' "$(java -version 2>&1 | sed -n '1p' || true)"
} > "$ENVIRONMENT_FILE"

build_count=0

for case_index in "${!SAMPLE_IDS[@]}"; do
    sample_id="${SAMPLE_IDS[$case_index]}"
    source_path="${SOURCE_PATHS[$case_index]}"
    pair_id="${PAIR_IDS[$case_index]}"
    cwe="${CWES[$case_index]}"
    label="${LABELS[$case_index]}"
    allocation="${ALLOCATIONS[$case_index]}"

    [[ -f "$source_path" ]] || die "source file not found: $source_path"

    # Compile from an opaque filename so retained STT_FILE symbols do not expose
    # stack/heap or ground-truth naming conventions.
    staged_source="$STAGED_SOURCE_DIR/${sample_id}.c"
    cp -- "$source_path" "$staged_source"

    for opt_index in "${!OPT_TAGS[@]}"; do
        opt_tag="${OPT_TAGS[$opt_index]}"
        opt_flag="${OPT_FLAGS[$opt_index]}"
        artifact_name="${sample_id}_${opt_tag}.elf"

        oracle="$ORACLE_DIR/$artifact_name"
        retained="$RETAINED_DIR/$artifact_name"
        stripped="$STRIPPED_DIR/$artifact_name"
        log="$LOG_DIR/${sample_id}_${opt_tag}.log"

        printf '[BUILD] %s %s\n' "$sample_id" "$opt_tag"
        if ! "$CC" "${COMMON_CFLAGS[@]}" "$opt_flag" "$staged_source" \
            "${COMMON_LDFLAGS[@]}" -o "$oracle" > "$log" 2>&1; then
            sed -n '1,240p' "$log" >&2
            die "compilation failed for $sample_id $opt_tag"
        fi

        cp -- "$oracle" "$retained"
        "$OBJCOPY" --strip-debug "$retained"

        cp -- "$oracle" "$stripped"
        "$STRIP" --strip-all "$stripped"

        oracle_hash="$(text_hash "$oracle")"
        retained_hash="$(text_hash "$retained")"
        stripped_hash="$(text_hash "$stripped")"

        [[ "$oracle_hash" == "$retained_hash" && "$oracle_hash" == "$stripped_hash" ]] ||
            die ".text mismatch for $sample_id $opt_tag"

        has_debug_sections "$oracle" || die "oracle lacks DWARF: $oracle"
        ! has_debug_sections "$retained" || die "retained artifact still has DWARF: $retained"
        ! has_debug_sections "$stripped" || die "stripped artifact still has DWARF: $stripped"

        section_exists "$retained" .symtab || die "retained artifact lacks .symtab: $retained"
        ! section_exists "$stripped" .symtab || die "stripped artifact still has .symtab: $stripped"

        for artifact in "$oracle" "$retained" "$stripped"; do
            ! has_executable_stack "$artifact" || die "executable stack detected: $artifact"
        done

        for analysis_artifact in "$retained" "$stripped"; do
            check_leakage "$analysis_artifact" ||
                die "prohibited benchmark information found in $analysis_artifact"
        done

        if nm -D "$oracle" 2>/dev/null | grep -E '__[[:alnum:]_]+_chk' >/dev/null; then
            die "FORTIFY-style checked import found in $oracle"
        fi

        compile_flags="${COMMON_CFLAGS[*]} $opt_flag ${COMMON_LDFLAGS[*]}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$sample_id" "$pair_id" "$cwe" "$label" "$allocation" "$opt_tag" \
            "$source_path" "$actual_gcc_version" "$actual_binutils_version" \
            "$compile_flags" "${oracle#$SCRIPT_DIR/}" "${retained#$SCRIPT_DIR/}" \
            "${stripped#$SCRIPT_DIR/}" "$oracle_hash" "$retained_hash" \
            "$stripped_hash" true >> "$MANIFEST"

        build_count=$((build_count + 1))
    done
done

if [[ -s "$PRIVATE_DIR/leakage_failures.txt" ]]; then
    die "leakage failures were recorded in $PRIVATE_DIR/leakage_failures.txt"
fi

printf '\nValidated %d source/optimization artifact families.\n' "$build_count"
printf 'Produced %d ELF files: oracle, retained, and stripped.\n' "$((build_count * 3))"
printf 'Private manifest: %s\n' "$MANIFEST"
printf 'Environment record: %s\n' "$ENVIRONMENT_FILE"
