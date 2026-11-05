#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    command -v jq >/dev/null || skip "jq required"

    TEST_DIR="$(mktemp -d)"
    MOCK_BIN="${TEST_DIR}/mockbin"
    ORIG_PATH="$PATH"
    mkdir -p "$MOCK_BIN"

    export PATH="${MOCK_BIN}:$ORIG_PATH"
    export SCRIPTPATH="$project_root"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export OUTPUT_VERBOSITY=1
    export AXIOM=false

    export dir="${TEST_DIR}/target"
    export called_fn_dir="${dir}/.called_fn"
    export LOGFILE="${dir}/.tmp/test.log"
    export tools="${TEST_DIR}/tools"

    mkdir -p "${dir}/.tmp" "${dir}/webs" "${dir}/vulns" "$called_fn_dir"
    cd "$dir" || exit 1
    : >"$LOGFILE"

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    export tools="${TEST_DIR}/tools"
    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only
    set -eo pipefail

    export NEWSCAN=true DIFF=false DEEP=false DRY_RUN=false PROXYCHAINS=false
    export TIMEOUT_CMD="" domain="example.com" NEWSCAN_IMAGE="newscan:test"
    export NEWSCAN_TARGETS_FILE="" NEWSCAN_MAX_TARGETS=25 NEWSCAN_URL_SEED=true
    export outOfScope_file=""
    export DOCKER_CALLS="${TEST_DIR}/docker_calls"
    export NEWSCAN_FIXTURE="${project_root}/tests/fixtures/newscan/newscan_sample.json"
    : >"$DOCKER_CALLS"

    create_mock_docker
    create_mock_anew
}

teardown() {
    PATH="$ORIG_PATH"
    cd /
    rm -rf "$TEST_DIR"
}

create_mock_docker() {
    cat >"${MOCK_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${DOCKER_CALLS:?}"
case "$1" in
    info) exit 0 ;;
    image) [[ "${MOCK_NO_IMAGE:-0}" == 1 ]] && exit 1; [[ "$2" == ls ]] && echo "test"; exit 0 ;;
    rm) exit 0 ;;
    run)
        out="" prev=""
        for a in "$@"; do
            [[ "$prev" == "-v" && "$a" == *:/out ]] && out="${a%:/out}"
            prev="$a"
        done
        [[ "${MOCK_RUN_RC:-1}" == 2 ]] && exit 2
        cp "${NEWSCAN_FIXTURE:?}" "$out/newscan.json"
        exit 1 ;;
esac
EOF
    chmod +x "${MOCK_BIN}/docker"
}

create_mock_anew() {
    cat >"${MOCK_BIN}/anew" <<'EOF'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
    quiet=true
    shift
fi
outfile="$1"
mkdir -p "$(dirname "$outfile")"
touch "$outfile"
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! grep -Fxq -- "$line" "$outfile"; then
        printf '%s\n' "$line" >>"$outfile"
        if [[ "$quiet" != true ]]; then
            printf '%s\n' "$line"
        fi
    fi
done
EOF
    chmod +x "${MOCK_BIN}/anew"
}

run_lines() {
    grep -c '^run ' "$DOCKER_CALLS" || true
}

# Positional target of a recorded `docker run` line: the argument after "-m newscan".
run_targets() {
    awk '$1 == "run" { for (i = 1; i < NF; i++) if ($i == "-m" && $(i + 1) == "newscan") { print $(i + 2); break } }' \
        "$DOCKER_CALLS" | sort
}

@test "newscan_checks: disabled flag skips without docker or checkpoint" {
    export NEWSCAN=false
    printf '%s\n' "https://api.example.com" >webs/webs_all.txt

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_lines)" -eq 0 ]
    [ ! -f "${called_fn_dir}/.newscan_checks" ]
}

@test "newscan_checks: one docker run per live web origin, AI false positives dropped" {
    printf '%s\n' "https://api.example.com" "https://app.example.com:8443" >webs/webs_all.txt

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_lines)" -eq 2 ]
    [ "$(run_targets)" = "$(printf '%s\n' https://api.example.com https://app.example.com:8443)" ]
    grep -Fq "[HIGH] https://api.example.com GET /v1/users/{id} - Broken object level authorization" vulns/newscan.txt
    [ "$(grep -Fc "Likely false positive" vulns/newscan.txt || true)" -eq 0 ]
    [ -f vulns/newscan/api.example.com/newscan.json ]
    [ -f vulns/newscan/app.example.com_8443/newscan.json ]
    [ "$(cat vulns/newscan/api.example.com/exit_code)" = "1" ]
    [ -f "${called_fn_dir}/.newscan_checks" ]
}

@test "newscan_checks: seeds each origin only with its own URLs" {
    printf '%s\n' "https://api.example.com" "https://app.example.com:8443" "https://www.example.com" >webs/webs_all.txt
    printf '%s\n' \
        "https://api.example.com/v1/users" \
        "https://api.example.com/v1/orders?id=1" \
        "https://app.example.com:8443/login" \
        "https://other.example.net/x" >webs/url_extract.txt

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(cat vulns/newscan/api.example.com/seed_urls.txt)" = "$(printf '%s\n' https://api.example.com/v1/users 'https://api.example.com/v1/orders?id=1')" ]
    [ "$(cat vulns/newscan/app.example.com_8443/seed_urls.txt)" = "https://app.example.com:8443/login" ]
    [ ! -s vulns/newscan/www.example.com/seed_urls.txt ]
    grep -E '^run .* https://api\.example\.com .*--url-list /out/seed_urls\.txt' "$DOCKER_CALLS"
    grep -E '^run .* https://app\.example\.com:8443 .*--url-list /out/seed_urls\.txt' "$DOCKER_CALLS"
    [ "$(grep -Ec '^run .* https://www\.example\.com .*--url-list' "$DOCKER_CALLS" || true)" -eq 0 ]
    [ "$(grep -Fc "other.example.net" "$DOCKER_CALLS" || true)" -eq 0 ]
}

@test "newscan_checks: user target list is normalized, scoped and injection-safe" {
    local targets="${TEST_DIR}/targets.txt"
    printf '%s\n' \
        "api.example.com" \
        "https://shop.example.com/cart?x=1" \
        "evil.com" \
        "https://a.example.com;id" \
        '$(touch pwned)' >"$targets"
    export NEWSCAN_TARGETS_FILE="$targets"

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_targets)" = "$(printf '%s\n' https://api.example.com https://shop.example.com)" ]
    [ "$(grep -Fc "evil.com" "$DOCKER_CALLS" || true)" -eq 0 ]
    [ -z "$(find "$TEST_DIR" -name pwned)" ]
    [ ! -e /pwned ]
    grep -Fq "rejected 2 malformed" "$LOGFILE"
}

@test "newscan_checks: NEWSCAN_MAX_TARGETS caps origins unless DEEP" {
    printf '%s\n' "https://a.example.com" "https://b.example.com" "https://c.example.com" >webs/webs_all.txt
    export NEWSCAN_MAX_TARGETS=1

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_lines)" -eq 1 ]

    : >"$DOCKER_CALLS"
    rm -f "${called_fn_dir}/.newscan_checks"
    export DEEP=true
    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_lines)" -eq 3 ]
}

@test "newscan_checks: scan failures are reported but do not fail the module" {
    printf '%s\n' "https://api.example.com" "https://app.example.com" >webs/webs_all.txt
    export MOCK_RUN_RC=2

    run newscan_checks
    [ "$status" -eq 0 ]
    [[ "$output" == *"could not complete"* ]]
    [ "$(cat vulns/newscan/api.example.com/exit_code)" = "2" ]
    [ "$(cat vulns/newscan/app.example.com/exit_code)" = "2" ]
}

@test "newscan_checks: missing image warns and leaves no checkpoint" {
    printf '%s\n' "https://api.example.com" >webs/webs_all.txt
    export MOCK_NO_IMAGE=1
    unset NEWSCAN_IMAGE

    run newscan_checks
    [ "$status" -eq 0 ]
    [[ "$output" == *"not loaded"* ]]
    [ "$(run_lines)" -eq 0 ]
    [ ! -f "${called_fn_dir}/.newscan_checks" ]
}

@test "newscan_checks: PROXYCHAINS skips because container traffic cannot be proxied" {
    printf '%s\n' "https://api.example.com" >webs/webs_all.txt
    export PROXYCHAINS=true

    run newscan_checks
    [ "$status" -eq 0 ]
    [[ "$output" == *"PROXYCHAINS cannot route NewScan"* ]]
    [ "$(run_lines)" -eq 0 ]
    [ ! -f "${called_fn_dir}/.newscan_checks" ]
}

@test "newscan_checks: dry run executes no docker run" {
    printf '%s\n' "https://api.example.com" >webs/webs_all.txt
    export DRY_RUN=true

    run newscan_checks
    [ "$status" -eq 0 ]
    [ "$(run_lines)" -eq 0 ]
}

@test "export_findings_jsonl: includes normalized NewScan findings" {
    printf '%s\n' "https://api.example.com" >webs/webs_all.txt
    run newscan_checks
    [ "$status" -eq 0 ]

    export_findings_jsonl
    [ "$(jq -c 'select(.tool == "newscan" and .severity == "high") | .host' report/findings_normalized.jsonl)" = '"api.example.com"' ]
    [ "$(jq -r 'select(.tool == "newscan") | .source_file' report/findings_normalized.jsonl | sort -u)" = "vulns/newscan.jsonl" ]
}
