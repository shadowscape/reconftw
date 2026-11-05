#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Vulnerability scanning module
# Contains: xss, ssrf_checks, crlf_checks, lfi, ssti,
#           sqli, test_ssl, spraying, command_injection, 4xxbypass,
#           smuggling, webcache, fuzzparams, nuclei_dast, fray_checks,
#           newscan_checks
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

function xss() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "XSS Analysis"

        # Process gf/xss.txt with qsreplace and Gxss
        if [[ -s "gf/xss.txt" ]]; then
            _print_msg INFO "Running: XSS Payload Generation"
            run_command qsreplace FUZZ <"gf/xss.txt" | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' \
                | anew -q ".tmp/xss_reflected.txt"
        fi

        # Determine whether to use Axiom or Katana for scanning
        if [[ $AXIOM != true ]]; then
            # Using Katana
            if [[ $DEEP == true ]]; then
                DEPTH=3
            else
                DEPTH=2
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

                # Run Dalfox with Katana output
                if [[ -s ".tmp/xss_reflected.txt" ]]; then
                    _print_msg INFO "Running: Dalfox with Katana"
                    run_command dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav $OPTIONS -d "$DEPTH" <".tmp/xss_reflected.txt" 2>>"$LOGFILE" |
                        anew -q "vulns/xss.txt"
                fi

            
        else
            # Using Axiom
            if [[ $DEEP == true ]]; then
                DEPTH=3
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            else
                DEPTH=2
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

            # Run Dalfox with Axiom-scan output
            if [[ -s ".tmp/xss_reflected.txt" ]]; then
                _print_msg INFO "Running: Dalfox with Axiom"
                run_command axiom-scan ".tmp/xss_reflected.txt" -m dalfox --skip-bav $OPTIONS -d "$DEPTH" -o "vulns/xss.txt" $AXIOM_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        end_func "Results are saved in vulns/xss.txt" "${FUNCNAME[0]}"
    else
        if [[ $XSS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/xss.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function ssrf_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] \
        && [[ -s "gf/ssrf.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSRF Checks"

        # Handle COLLAB_SERVER configuration
        if [[ -z $COLLAB_SERVER ]]; then
            interactsh-client &>.tmp/ssrf_callback.txt &
            INTERACTSH_PID=$!
            # Ensure interactsh is killed on function exit (prevents orphan processes)
            trap 'kill "$INTERACTSH_PID" 2>/dev/null; trap - RETURN' RETURN
            sleep 2

            # Extract FFUFHASH from interactsh_callback.txt
            COLLAB_SERVER_FIX="FFUFHASH.$(tail -n1 .tmp/ssrf_callback.txt | cut -c 16-)"
            COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
            INTERACT=true
        else
            COLLAB_SERVER_FIX="FFUFHASH.$(echo "$COLLAB_SERVER" | sed -r "s|https?://||")"
            INTERACT=false
        fi

        # Determine whether to proceed based on DEEP flag or URL count
        URL_COUNT=$(wc -l <"gf/ssrf.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: SSRF Payload Generation"

            # Generate classic callback payloads.
            run_command qsreplace "$COLLAB_SERVER_FIX" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"
            run_command qsreplace "$COLLAB_SERVER_URL" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"

            # Run FFUF to find requested URLs.
            _print_msg INFO "Running: FFUF for SSRF Requested URLs"
            run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf.txt" -u "FUZZ" 2>/dev/null \
                | anew -q "vulns/ssrf_requested.txt"

            # Run FFUF with header injection for SSRF.
            _print_msg INFO "Running: FFUF for SSRF Requested Headers with callback tokens"
            run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${headers_inject}:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t "$FFUF_THREADS" \
                -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"
            run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${headers_inject}:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t "$FFUF_THREADS" \
                -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

            # Additional protocol payloads (gopher/dict/file/metadata endpoints).
            local ssrf_payloads_file="${SCRIPTPATH}/config/ssrf_payloads.txt"
            if [[ -s "$ssrf_payloads_file" ]]; then
                : >".tmp/tmp_ssrf_protocols.txt"
                while IFS= read -r payload || [[ -n "$payload" ]]; do
                    [[ -z "$payload" || "$payload" =~ ^# ]] && continue
                    payload="${payload//\{COLLAB\}/$COLLAB_SERVER_FIX}"
                    payload="${payload//\{COLLAB_URL\}/$COLLAB_SERVER_URL}"
                        run_command qsreplace "$payload" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf_protocols.txt"
                done <"$ssrf_payloads_file"

                if [[ -s ".tmp/tmp_ssrf_protocols.txt" ]]; then
                    _print_msg INFO "Running: FFUF for SSRF alternate protocols"
                    run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf_protocols.txt" -u "FUZZ" \
                        -mr "${SSRF_ALT_MATCH_REGEX:-169\\.254\\.169\\.254|latest/meta-data|root:|127\\.0\\.0\\.1|localhost|gopher://|dict://|file://}" 2>/dev/null \
                        | grep "URL" | sed 's/| URL | //' | anew -q "vulns/ssrf_alt_protocols.txt"
                fi
            fi

            # Allow time for callbacks to be received.
            sleep 5

            # Process SSRF callback results if INTERACT is enabled.
            if [[ $INTERACT == true ]] && [[ -s ".tmp/ssrf_callback.txt" ]]; then
                tail -n +11 .tmp/ssrf_callback.txt | anew -q "vulns/ssrf_callback.txt"
                if ! NUMOFLINES=$(tail -n +12 .tmp/ssrf_callback.txt | sed '/^$/d' | wc -l); then
                    NUMOFLINES=0
                fi
                notification "SSRF: ${NUMOFLINES} callbacks received" info
            fi

            end_func "Results are saved in vulns/ssrf_* (including alternate protocols)" "${FUNCNAME[0]}"
        else
            end_func "Skipping SSRF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

        # Terminate interactsh-client if it was started
        if [[ $INTERACT == true ]] && [[ -n "${INTERACTSH_PID:-}" ]]; then
            kill "$INTERACTSH_PID" 2>/dev/null || true
            unset INTERACTSH_PID
        fi

    else
        if [[ $SSRF_CHECKS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/ssrf.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function crlf_checks() {

    # Create necessary directories
    if ! ensure_dirs webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v crlfuzz >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: crlfuzz not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "CRLF Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: CRLF Fuzzing"

            # Run CRLFuzz
            run_command crlfuzz -l "webs/webs_all.txt" -o "vulns/crlf.txt" 2>>"$LOGFILE" >/dev/null

            end_func "Results are saved in vulns/crlf.txt" "${FUNCNAME[0]}"
        else
            end_func "Skipping CRLF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi
    else
        if [[ $CRLF_CHECKS == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

_lfi_emit_single_param_candidates() {
    local url="$1"
    [[ "$url" == *"?"* ]] || return 0

    local base="${url%%\?*}"
    local query_and_fragment="${url#*\?}"
    local query="$query_and_fragment"
    local fragment=""

    if [[ "$query_and_fragment" == *"#"* ]]; then
        query="${query_and_fragment%%#*}"
        fragment="#${query_and_fragment#*#}"
    fi
    [[ -n "$query" ]] || return 0

    local IFS='&'
    local -a params=()
    read -r -a params <<<"$query"
    [[ ${#params[@]} -gt 0 ]] || return 0

    local -A seen=()
    local idx j param key rebuilt other_param other_key new_param
    for idx in "${!params[@]}"; do
        param="${params[$idx]}"
        key="${param%%=*}"
        [[ -n "$key" ]] || continue
        if [[ -n "${seen[$key]+x}" ]]; then
            continue
        fi
        seen["$key"]=1

        rebuilt=""
        for j in "${!params[@]}"; do
            other_param="${params[$j]}"
            other_key="${other_param%%=*}"
            if [[ "$other_key" == "$key" ]]; then
                new_param="${other_key}=FUZZ"
            else
                new_param="$other_param"
            fi

            if [[ -n "$rebuilt" ]]; then
                rebuilt="${rebuilt}&${new_param}"
            else
                rebuilt="$new_param"
            fi
        done

        [[ -n "$rebuilt" ]] && printf "%s?%s%s\n" "$base" "$rebuilt" "$fragment"
    done
}

_lfi_prepare_candidates() {
    local input_file="$1"
    local output_file="$2"
    local all_candidates=".tmp/tmp_lfi_all.txt"
    : >"$all_candidates"
    : >"$output_file"

    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        _lfi_emit_single_param_candidates "$url"
    done <"$input_file" | sort -u >"$all_candidates"

    cat "$all_candidates" >"$output_file"

    if [[ "${LFI_MAX_URLS:-0}" -gt 0 ]] && [[ -s "$output_file" ]]; then
        head -n "${LFI_MAX_URLS}" "$output_file" >"${output_file}.limited"
        mv "${output_file}.limited" "$output_file"
    fi
}

function lfi() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] \
        && [[ -s "gf/lfi.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "LFI Checks"

        # Ensure gf/lfi.txt is not empty
        if [[ -s "gf/lfi.txt" ]]; then
            _print_msg INFO "Running: LFI Payload Generation"

            # Generate one candidate per parameter and prioritize likely LFI sinks first.
            _lfi_prepare_candidates "gf/lfi.txt" ".tmp/tmp_lfi.txt"
            if [[ ! -s ".tmp/tmp_lfi.txt" ]]; then
                end_func "No per-parameter LFI candidates generated." "${FUNCNAME[0]}" "SKIP_NOINPUT"
                return 0
            fi

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_lfi.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                _print_msg INFO "Running: LFI Fuzzing with FFUF"

                local lfi_interlace_threads="${LFI_INTERLACE_THREADS:-4}"
                local lfi_ffuf_threads="${LFI_FFUF_THREADS:-20}"
                local lfi_ffuf_rate="${LFI_FFUF_RATELIMIT:-50}"
                local lfi_ffuf_timeout="${LFI_FFUF_TIMEOUT:-10}"
                local lfi_ffuf_maxtime="${LFI_FFUF_MAXTIME:-90}"
                local lfi_follow_redirects="${LFI_FOLLOW_REDIRECTS:-false}"
                local lfi_redirect_flag=""
                [[ "$lfi_follow_redirects" == true ]] && lfi_redirect_flag="-r"

                # argv-safe parallel replacement for interlace -c. Each ffuf runs in a
                # background subshell, writing its output to a per-target temp file;
                # outputs are merged once all workers complete. Concurrency capped at
                # lfi_interlace_threads (same as the removed `interlace -threads`).
                local -a _lfi_ffuf_args
                _lfi_ffuf_args=(-v -noninteractive)
                [[ -n "$lfi_redirect_flag" ]] && _lfi_ffuf_args+=("$lfi_redirect_flag")
                _lfi_ffuf_args+=(
                    -t "$lfi_ffuf_threads"
                    -rate "$lfi_ffuf_rate"
                    -timeout "$lfi_ffuf_timeout"
                    -maxtime "$lfi_ffuf_maxtime"
                    -H "$HEADER"
                    -w "$lfi_wordlist"
                    -mr "root:x:"
                )
                local _lfi_parts
                _lfi_parts=$(mktemp -d)
                while IFS= read -r _lfi_target; do
                    [[ -z "$_lfi_target" ]] && continue
                    (
                        _lfi_hash=$(printf '%s' "$_lfi_target" | sha256sum | cut -d' ' -f1)
                        ffuf "${_lfi_ffuf_args[@]}" -u "$_lfi_target" \
                            >"$_lfi_parts/$_lfi_hash" 2>>"$LOGFILE" || true
                    ) &
                    _throttle_jobs "$lfi_interlace_threads"
                done <".tmp/tmp_lfi.txt"
                wait
                cat "$_lfi_parts"/* 2>/dev/null \
                    | grep "URL" | sed 's/| URL | //' | anew -q "vulns/lfi.txt"
                rm -rf "$_lfi_parts"

                end_func "Results are saved in vulns/lfi.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping LFI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/lfi.txt file found, LFI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $LFI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/lfi.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function ssti() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] \
        && [[ -s "gf/ssti.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSTI Checks"

        # Ensure gf/ssti.txt is not empty
        if [[ -s "gf/ssti.txt" ]]; then
            local ssti_engine="${SSTI_ENGINE:-TInjA}"

            _print_msg INFO "Running: SSTI Payload Generation"

            # Process ssti.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/ssti.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_ssti.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_ssti.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then
                : >".tmp/ssti_candidates.txt"

                if [[ "$ssti_engine" == "SSTImap" ]]; then
                    # --- SSTImap branch ---
                    local sstimap_bin="${tools}/SSTImap/sstimap.py"
                    local sstimap_python="${tools}/SSTImap/venv/bin/python3"
                    if [[ ! -f "$sstimap_bin" ]] || [[ ! -f "$sstimap_python" ]]; then
                        end_func "Skipping SSTI: SSTImap not installed." "${FUNCNAME[0]}" "SKIP_MISSING_TOOL"
                        return 0
                    fi

                    _print_msg INFO "Running: SSTI Checks with SSTImap (level ${SSTIMAP_LEVEL:-1})"

                    local -a sstimap_cmd=("$sstimap_python" "$sstimap_bin"
                        --level "${SSTIMAP_LEVEL:-1}"
                        --no-color
                    )
                    [[ "${SSTIMAP_LEGACY:-false}" == "true" ]] && sstimap_cmd+=(--legacy)
                    [[ "${SSTIMAP_GENERIC:-false}" == "true" ]] && sstimap_cmd+=(--generic)
                    [[ "${SSTIMAP_DELAY:-0}" -gt 0 ]] && sstimap_cmd+=(--delay "${SSTIMAP_DELAY}")
                    [[ -n "${HEADER:-}" ]] && sstimap_cmd+=(-H "${HEADER}")

                    sstimap_cmd+=(--load-urls ".tmp/tmp_ssti.txt")

                    if ! run_command "${sstimap_cmd[@]}" 2>>"$LOGFILE" | tee ".tmp/sstimap_raw.txt" | grep -i "confirmed\|identified" | grep -oP 'https?://[^\s]+' | anew -q ".tmp/ssti_candidates.txt"; then
                        log_note "ssti: SSTImap execution failed or no findings" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                else
                    # --- TInjA branch (default) ---
                    if ! command -v TInjA >/dev/null 2>&1; then
                        end_func "Skipping SSTI: TInjA not installed." "${FUNCNAME[0]}" "SKIP_MISSING_TOOL"
                        return 0
                    fi

                    _print_msg INFO "Running: SSTI Checks with TInjA"
                    local TInjA_report_dir="$dir/.tmp/TInjA"
                    mkdir -p "$TInjA_report_dir"
                    local -a TInjA_cmd=(TInjA url --reportpath "${TInjA_report_dir}/" --ratelimit "${TInjA_RATELIMIT:-0}" --timeout "${TInjA_TIMEOUT:-15}" --verbosity 0)
                    if [[ -n "${HEADER:-}" ]]; then
                        TInjA_cmd+=(-H "${HEADER}")
                    fi
                    while IFS= read -r u; do
                        [[ -n "$u" ]] && TInjA_cmd+=(--url "$u")
                    done <".tmp/tmp_ssti.txt"

                    if ! run_command "${TInjA_cmd[@]}" 2>>"$LOGFILE" >/dev/null; then
                        log_note "ssti: TInjA execution failed, no findings collected" "${FUNCNAME[0]}" "${LINENO}"
                    fi

                    local report_file=""
                    report_file=$(ls -1t "${TInjA_report_dir}"/*.jsonl 2>/dev/null | head -n 1 || true)
                    if [[ -n "$report_file" && -s "$report_file" ]]; then
                        jq -r 'select((.isWebpageVulnerable == true) or any(.parameters[]?; .isParameterVulnerable == true)) | (.url // empty) + " [certainty:" + (.certainty // "unknown") + "]"' "$report_file" 2>/dev/null \
                            | sed '/^\s*$/d' \
                            | anew -q ".tmp/ssti_candidates.txt"
                    fi
                fi

                if [[ -s ".tmp/ssti_candidates.txt" ]]; then
                    cat ".tmp/ssti_candidates.txt" | anew -q "vulns/ssti_${ssti_engine}.txt"
                    cat ".tmp/ssti_candidates.txt" | anew -q "vulns/ssti.txt"
                fi

                end_func "Results are saved in vulns/ssti.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping SSTI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/ssti.txt file found, SSTI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $SSTI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/ssti.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function sqli() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] \
        && [[ -s "gf/sqli.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SQLi Checks"

        # Ensure gf/sqli.txt is not empty
        if [[ -s "gf/sqli.txt" ]]; then
            _print_msg INFO "Running: SQLi Payload Generation"

            # Process sqli.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/sqli.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_sqli.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                    # Check if SQLMAP is enabled and run SQLMap
                    if [[ $SQLMAP == true ]]; then
                        _print_msg INFO "Running: SQLMap for SQLi Checks"
                        run_command python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli.txt" -b -o --smart \
                            --batch --disable-coloring --random-agent --output-dir="vulns/sqlmap" 2>>"$LOGFILE" >/dev/null
                    fi
                                # Check if GHAURI is enabled and run Ghauri
                if [[ $GHAURI == true ]]; then
                    _print_msg INFO "Running: Ghauri for SQLi Checks"
                    mkdir -p .tmp/ghauri_parts
                    # argv-safe parallel replacement for interlace -c. Each target runs
                    # ghauri in a background subshell writing to its own per-target file.
                    while IFS= read -r _sqli_target; do
                        [[ -z "$_sqli_target" ]] && continue
                        (
                            _sqli_safe=$(printf '%s' "$_sqli_target" | sha256sum | cut -d' ' -f1)
                            ghauri -u "$_sqli_target" --batch -H "$HEADER" --force-ssl \
                                >".tmp/ghauri_parts/${_sqli_safe}.txt" 2>>"$LOGFILE" || true
                        ) &
                        _throttle_jobs "${INTERLACE_THREADS:-10}"
                    done <".tmp/tmp_sqli.txt"
                    wait
                    # Merge per-target outputs (each process writes its own file, so
                    # there is no concurrent-write corruption).
                    cat .tmp/ghauri_parts/*.txt 2>/dev/null | anew -q vulns/ghauri_log.txt || true
                    rm -rf .tmp/ghauri_parts
                fi

                end_func "Results are saved in vulns/sqlmap folder" "${FUNCNAME[0]}"
            else
                end_func "Skipping SQLi: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/sqli.txt file found, SQLi Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $SQLI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/sqli.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function test_ssl() {

    # Create necessary directories
    if ! ensure_dirs hosts vulns; then return 1; fi

    # Check if the function should run
    if should_run "TEST_SSL"; then

        start_func "${FUNCNAME[0]}" "SSL Test"

        # Handle multi-domain scenarios
        if [[ -n $multi ]] && [[ ! -f "$dir/hosts/ips.txt" ]]; then
            echo "$domain" >"$dir/hosts/ips.txt"
        fi

        # Run testssl.sh — prefer non-CDN IPs to avoid testing CDN TLS configs
        local testssl_input="$dir/hosts/ips.txt"
        if [[ -s "$dir/.tmp/ips_nocdn.txt" ]]; then
            testssl_input="$dir/.tmp/ips_nocdn.txt"
        fi
        _print_msg INFO "Running: SSL Test with testssl.sh"
        run_command "${tools}/testssl.sh/testssl.sh" --quiet --color 0 -U -iL "$testssl_input" 2>>"$LOGFILE" >"vulns/testssl.txt"

        end_func "Results are saved in vulns/testssl.txt" "${FUNCNAME[0]}"

    else
        if [[ $TEST_SSL == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "vulns/testssl.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function spraying() {

    # Create necessary directories
    if ! ensure_dirs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]] \
        && [[ -s "$dir/hosts/portscan_active.gnmap" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Password Spraying"

        # Ensure portscan_active.gnmap exists and is not empty
        if [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            print_warnf "File %s/hosts/portscan_active.gnmap does not exist or is empty." "$dir"
            end_func "Port scan results missing. Password Spraying aborted." "${FUNCNAME[0]}"
            return 1
        fi

        local spray_engine="${SPRAY_ENGINE:-brutespray}"
        if [[ "$spray_engine" == "brutus" ]]; then
            if [[ "${SPRAY_BRUTUS_ONLY_DEEP:-true}" == "true" && "${DEEP:-false}" != "true" ]]; then
                end_func "Brutus spraying is DEEP-gated (set DEEP=true or SPRAY_BRUTUS_ONLY_DEEP=false)" "${FUNCNAME[0]}" SKIP
                return 0
            fi
            if ! command -v brutus >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: brutus not found in PATH"
                end_func "Brutus not available, skipping" "${FUNCNAME[0]}" SKIP
                return 0
            fi

            local brutus_input=""
            if [[ -s "$dir/hosts/service_fingerprints.jsonl" ]]; then
                brutus_input="$dir/hosts/service_fingerprints.jsonl"
            elif [[ -s "$dir/hosts/naabu_open.txt" ]] && command -v nerva >/dev/null 2>&1; then
                run_command nerva --json -l "$dir/hosts/naabu_open.txt" -o "$dir/.tmp/service_fp_for_brutus.jsonl" 2>>"$LOGFILE" >/dev/null || true
                [[ -s "$dir/.tmp/service_fp_for_brutus.jsonl" ]] && brutus_input="$dir/.tmp/service_fp_for_brutus.jsonl"
            fi

            if [[ -z "$brutus_input" ]]; then
                end_func "No service fingerprint JSON input for brutus (run portscan with SERVICE_FINGERPRINT=true)" "${FUNCNAME[0]}" SKIP
                return 0
            fi

            local -a brutus_cmd=(brutus --json -o "$dir/vulns/brutus.jsonl")
            [[ -n "${BRUTUS_USERNAMES:-}" ]] && brutus_cmd+=(-u "$BRUTUS_USERNAMES")
            [[ -n "${BRUTUS_PASSWORDS:-}" ]] && brutus_cmd+=(-p "$BRUTUS_PASSWORDS")
            [[ -n "${BRUTUS_KEY_FILE:-}" ]] && brutus_cmd+=(-k "$BRUTUS_KEY_FILE")

            _print_msg INFO "Running: Password Spraying with Brutus"
            if ! run_command "${brutus_cmd[@]}" <"$brutus_input" 2>>"$LOGFILE" >/dev/null; then
                _print_msg WARN "Brutus command failed, continuing"
            fi
            end_func "Results are saved in vulns/brutus.jsonl" "${FUNCNAME[0]}"
            return 0
        fi

        if ! command -v brutespray >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: brutespray not found in PATH"
            end_func "BruteSpray not available, skipping" "${FUNCNAME[0]}" SKIP
            return 0
        fi

        _print_msg INFO "Running: Password Spraying with BruteSpray"
        brutespray -f "$dir/hosts/portscan_active.gnmap" -T "$BRUTESPRAY_CONCURRENCE" -o "$dir/vulns/brutespray" 2>>"$LOGFILE" >/dev/null
        end_func "Results are saved in vulns/brutespray folder" "${FUNCNAME[0]}"

    else
        if [[ $SPRAY == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function command_injection() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] \
        && [[ -s "gf/rce.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Command Injection Checks"

        # Ensure gf/rce.txt is not empty and process it
        if [[ -s "gf/rce.txt" ]]; then
            _print_msg INFO "Running: Command Injection Payload Generation"

            # Process rce.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/rce.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_rce.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_rce.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

    # Run Commix if enabled
    if [[ $COMMIX == true ]]; then
        _print_msg INFO "Running: Commix for Command Injection Checks"
        run_command commix --batch -m ".tmp/tmp_rce.txt" --output-dir "vulns/command_injection" 2>>"$LOGFILE" >/dev/null
    fi

                # Additional tools can be integrated here (e.g., Ghauri, sqlmap)

                end_func "Results are saved in vulns/command_injection folder" "${FUNCNAME[0]}"
            else
                end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/rce.txt file found, Command Injection Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $COMM_INJ == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/rce.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function 4xxbypass() {

    # Create necessary directories
    if ! ensure_dirs .tmp fuzzing vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        # Extract relevant URLs starting with 4xx but not 404
        grep -E '^4' "fuzzing/fuzzing_full.txt" 2>/dev/null | grep -Ev '^404' | awk '{print $3}' | anew -q ".tmp/403test.txt"

        # Count the number of URLs to process
        URL_COUNT=$(wc -l <".tmp/403test.txt")

        start_func "${FUNCNAME[0]}" "403 Bypass"

        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            # Run nomore403 in a subshell to avoid CWD pollution
            (
                cd "${tools}/nomore403" || exit 1
                ./nomore403 <"$dir/.tmp/403test.txt" >"$dir/.tmp/4xxbypass.txt" 2>>"$LOGFILE"
            )
            if [[ $? -ne 0 ]]; then
                print_warnf "nomore403 failed or directory not found."
                end_func "Failed during 403 Bypass." "${FUNCNAME[0]}"
                return 1
            fi

            # Append unique bypassed URLs to the vulns directory
            if [[ -s "$dir/.tmp/4xxbypass.txt" ]]; then
                cat "$dir/.tmp/4xxbypass.txt" | anew -q "vulns/4xxbypass.txt"
            fi

            end_func "Results are saved in vulns/4xxbypass.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping 403 Bypass: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $BYPASSER4XX == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function smuggling() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns/smuggling; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v smugglex >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: smugglex not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "HTTP Request Smuggling Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat "webs/webs.txt" "webs/webs_uncommon_ports.txt" 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: HTTP Request Smuggling Checks"

            # Run smugglex on the list of URLs
            cat "$dir/webs/webs_all.txt" | smugglex -f plain -o "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" >/dev/null

            # Append unique smuggling results to vulns directory
            if [[ -s "$dir/.tmp/smuggling.txt" ]]; then
                jq -c < "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" | anew -q "vulns/smuggling.txt"
            fi

            end_func "Findings are saved in vulns/smuggling.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping HTTP Request Smuggling: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $SMUGGLING == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "webs/webs_all.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function webcache() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v Web-Cache-Vulnerability-Scanner >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: Web-Cache-Vulnerability-Scanner not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Web Cache Poisoning Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: Web Cache Poisoning Checks"

            # Run Web-Cache-Vulnerability-Scanner in a subshell to avoid CWD pollution
            (
                cd "${tools}/Web-Cache-Vulnerability-Scanner" || exit 1
                Web-Cache-Vulnerability-Scanner -u "file:$dir/webs/webs_all.txt" -v 0 2>>"$LOGFILE" \
                    | anew -q "$dir/.tmp/webcache.txt"
            )
            if [[ $? -ne 0 ]]; then
                print_warnf "Web-Cache-Vulnerability-Scanner failed or directory not found."
            fi

            # Append unique findings to vulns/webcache.txt
            if [[ -s "$dir/.tmp/webcache.txt" ]]; then
                cat "$dir/.tmp/webcache.txt" | anew -q "vulns/webcache.txt"
            fi

            # Optional second engine (toxicache) to complement findings
            if [[ ${WEBCACHE_TOXICACHE:-true} == true ]] && command -v toxicache >/dev/null 2>&1; then
                local toxicache_out="$dir/.tmp/webcache_toxicache.txt"
                run_command toxicache -i "$dir/webs/webs_all.txt" -o "$toxicache_out" -t "${TOXICACHE_THREADS:-70}" -ua "${TOXICACHE_USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64)}" 2>>"$LOGFILE" >/dev/null || true
                if [[ -s "$toxicache_out" ]]; then
                    cat "$toxicache_out" | anew -q "vulns/webcache_toxicache.txt"
                fi
            fi

            end_func "Results are saved in vulns/webcache.txt" "${FUNCNAME[0]}"

        else
            end_func "Skipping Web Cache Poisoning: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $WEBCACHE == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function fuzzparams() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if [[ $AXIOM != true ]]; then
            if ! command -v nuclei >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei binary not found in PATH - install nuclei first"
                return 0
            fi
            if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei templates not found at '${NUCLEI_TEMPLATES_PATH}'"
                return 0
            fi
        fi
        start_func "${FUNCNAME[0]}" "Fuzzing Parameters Values Checks"

        if [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            _print_msg WARN "File webs/url_extract_nodupes.txt is missing or empty."
            end_func "Skipping fuzzparams: missing URL candidates." "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Determine if we should proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt" 2>/dev/null || echo 0)
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT2 ]]; then

            #cent update -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null

            if [[ $AXIOM != true ]]; then
                _print_msg INFO "Running: Nuclei Setup and Execution"

                # Update Nuclei once per run
                maybe_update_nuclei

                        # Execute Nuclei with the fuzzing templates

                        run_command nuclei -l webs/url_extract_nodupes.txt -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} -t ${NUCLEI_TEMPLATES_PATH}/dast -dast -j -o ".tmp/fuzzparams_json.txt" <"webs/url_extract_nodupes.txt" 2>>"$LOGFILE" >/dev/null

                    else

                        _print_msg INFO "Running: Axiom with Nuclei"

                        run_command axiom-scan webs/url_extract_nodupes.txt -m nuclei \
                            -dast -nh -rl "$NUCLEI_RATELIMIT" \
                            -silent -retries 2 "$NUCLEI_EXTRA_ARGS" -dast -j -o ".tmp/fuzzparams_json.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

                    fi

                

            # Convert JSON output to text
            if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/fuzzparams_json.txt >.tmp/fuzzparams.txt
            else
                : >.tmp/fuzzparams.txt
                log_note "fuzzparams: nuclei produced no JSON output; skipping conversion" "${FUNCNAME[0]}" "${LINENO}"
            fi

            # Append unique results to vulns/fuzzparams.txt
            if [[ -s ".tmp/fuzzparams.txt" ]]; then
                cat ".tmp/fuzzparams.txt" | anew -q "vulns/fuzzparams.txt"
            fi

            # Faraday integration
            if [[ $FARADAY == true ]]; then
                # Check if the Faraday server is running
                if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "Faraday server is not running. Skipping Faraday integration."
                else
                    if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                        faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
                    fi
                fi
            fi

            end_func "Results are saved in vulns/fuzzparams.txt" "${FUNCNAME[0]}"

        else
            end_func "Fuzzing Parameters Values: Too many entries to test, try with --deep flag" "${FUNCNAME[0]}"
        fi

    else
        if [[ $FUZZPARAMS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

_nuclei_dast_collect_targets() {
    : >".tmp/nuclei_dast_targets.txt"

    # Baseline web targets.
    if [[ -s "webs/webs_all.txt" ]]; then
        grep -aE '^https?://' "webs/webs_all.txt" | anew -q ".tmp/nuclei_dast_targets.txt"
    fi
    if [[ -s "webs/url_extract_nodupes.txt" ]]; then
        grep -aE '^https?://' "webs/url_extract_nodupes.txt" | anew -q ".tmp/nuclei_dast_targets.txt"
    fi

    # Candidate URLs generated by GF patterns across vuln modules.
    local gf_file
    for gf_file in gf/*.txt; do
        [[ -s "$gf_file" ]] || continue
        grep -aE '^https?://' "$gf_file" | anew -q ".tmp/nuclei_dast_targets.txt"
    done

    sort -u ".tmp/nuclei_dast_targets.txt" -o ".tmp/nuclei_dast_targets.txt" 2>/dev/null || true
}

function nuclei_dast() {

    if ! ensure_dirs .tmp webs gf vulns nuclei_output; then return 1; fi

    # nuclei_dast is part of the vulnerability scanning pipeline.
    # If the user enables vulns (e.g. `-a`), force-enable this DAST pass to replace deprecated single-purpose modules.
    local dast_enabled="${NUCLEI_DAST:-true}"
    if [[ ${VULNS_GENERAL:-false} == true ]]; then
        if [[ ${NUCLEI_DAST:-true} != true ]]; then
            _print_msg WARN "NUCLEI_DAST is forced enabled when VULNS_GENERAL=true (e.g. -a)."
        fi
        dast_enabled=true
    fi

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ "$dast_enabled" == true ]]; then
        if [[ $AXIOM != true ]]; then
            if ! command -v nuclei >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei binary not found in PATH - install nuclei first"
                return 0
            fi
            if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei templates not found at '${NUCLEI_TEMPLATES_PATH}'"
                return 0
            fi
        fi
        start_func "${FUNCNAME[0]}" "Nuclei DAST Scanner"
        maybe_update_nuclei

        _nuclei_dast_collect_targets
        if [[ ! -s ".tmp/nuclei_dast_targets.txt" ]]; then
            end_func "No DAST targets available from webs/url/gf inputs." "${FUNCNAME[0]}" "SKIP_NOINPUT"
            return 0
        fi

        local url_count
        url_count=$(wc -l <".tmp/nuclei_dast_targets.txt" 2>/dev/null || echo 0)
        if [[ $DEEP != true ]] && [[ "$url_count" -gt "${DEEP_LIMIT2:-1500}" ]]; then
            end_func "Skipping Nuclei DAST: too many targets (${url_count}), use --deep." "${FUNCNAME[0]}"
            return 0
        fi

        local dast_templates="${NUCLEI_DAST_TEMPLATE_PATH:-${NUCLEI_TEMPLATES_PATH}/dast}"
        if [[ $AXIOM != true ]]; then
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_command nuclei -l ".tmp/nuclei_dast_targets.txt" -dast -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 \
                $NUCLEI_EXTRA_ARGS $NUCLEI_DAST_EXTRA_ARGS -t "$dast_templates" -j -o ".tmp/nuclei_dast_json_raw.txt" \
                2>>"$LOGFILE" >/dev/null
        else
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_command axiom-scan ".tmp/nuclei_dast_targets.txt" -m nuclei -dast -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 \
                $NUCLEI_EXTRA_ARGS $NUCLEI_DAST_EXTRA_ARGS -t "$dast_templates" -j -o ".tmp/nuclei_dast_json_raw.txt" \
                $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
        fi

        if [[ -s ".tmp/nuclei_dast_json_raw.txt" ]]; then
            jq -c '. + {scan_scope:"dast"}' ".tmp/nuclei_dast_json_raw.txt" 2>/dev/null >"nuclei_output/dast_json.txt"
            jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host)] | .[]' \
                "nuclei_output/dast_json.txt" 2>/dev/null | anew -q "vulns/nuclei_dast.txt"
        else
            : >"nuclei_output/dast_json.txt"
        fi

        if [[ $FARADAY == true ]] && [[ -s "nuclei_output/dast_json.txt" ]]; then
            if faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei "nuclei_output/dast_json.txt" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        end_func "Results are saved in nuclei_output/dast_json.txt and vulns/nuclei_dast.txt" "${FUNCNAME[0]}"
    else
        if [[ "$dast_enabled" == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function fray_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp vulns; then return 1; fi

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FRAY_EXTRA == true ]]; then
        if ! command -v fray >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: fray not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Fray WAF-aware payload testing"

        ensure_webs_all || true

        if [[ -s "webs/webs_all.txt" ]]; then
            local _targets="webs/webs_all.txt"

            # Apply DEEP_LIMIT gate
            if [[ $DEEP != true ]]; then
                local _count
                _count=$(wc -l < "$_targets" | tr -d ' ')
                if (( _count > DEEP_LIMIT )); then
                    head -n "$DEEP_LIMIT" "$_targets" > .tmp/fray_targets.txt
                    _targets=".tmp/fray_targets.txt"
                    _print_msg INFO "Limiting Fray to ${DEEP_LIMIT} targets (DEEP mode disabled)"
                fi
            fi

            local total_findings=0

            IFS=',' read -ra _fray_categories <<< "$FRAY_CATEGORIES"
            for _fcat in "${_fray_categories[@]}"; do
                _print_msg INFO "Fray testing category: ${_fcat}"

                cat "$_targets" | fray test -c "$_fcat" \
                    --max "${FRAY_MAX_PAYLOADS:-20}" \
                    -t "${FRAY_TIMEOUT:-10}" \
                    -d "${FRAY_DELAY:-0.5}" \
                    --json 2>>"$LOGFILE" | grep '^{' > ".tmp/fray_${_fcat}.json" || true

                # Extract targets with bypasses from JSONL output
                if [[ -s ".tmp/fray_${_fcat}.json" ]]; then
                    jq -r 'select(.bypassed != null and .bypassed > 0) |
                        "\(.target) [bypass_rate:\(.bypass_rate)] \(.bypassed)/\(.total) payloads bypassed WAF"' \
                        ".tmp/fray_${_fcat}.json" >> "vulns/fray_${_fcat}.txt" 2>/dev/null || true

                    if [[ -s "vulns/fray_${_fcat}.txt" ]]; then
                        local _cat_count
                        _cat_count=$(wc -l < "vulns/fray_${_fcat}.txt" | tr -d ' ')
                        total_findings=$((total_findings + _cat_count))
                        append_assets_from_file finding value "vulns/fray_${_fcat}.txt"
                    fi
                fi
            done

            end_func "${total_findings} Fray findings saved in vulns/fray_*.txt" "${FUNCNAME[0]}"
        else
            end_func "No websites to scan" "${FUNCNAME[0]}"
        fi
    else
        if [[ $FRAY_EXTRA == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

# NewScan ships only as a local Docker image (proprietary, no public repo), so it runs
# through `docker run` instead of a ${tools}/<repo>/venv like the other Python tools.
# One NewScan run covers exactly one origin, so every live web origin gets its own run.
function _newscan_resolve_image() {
    if [[ -n "${NEWSCAN_IMAGE:-}" ]]; then
        printf '%s\n' "$NEWSCAN_IMAGE"
        return 0
    fi
    docker image ls newscan --format '{{.Tag}}' 2>/dev/null | grep -v '^<none>$' \
        | sort -V | tail -n 1 | sed 's/^/newscan:/'
}

function _newscan_slug() {
    local slug="${1#*://}"
    printf '%s\n' "${slug//[^A-Za-z0-9._-]/_}"
}

# Normalize subdomains/URLs from $1 into unique scheme://host[:port] origins on stdout.
# Bare hosts reuse their live origin from webs/webs_all.txt, else default to https.
# Anything that is not a plain hostname (userinfo, shell metacharacters, spaces) is rejected.
function _newscan_origins() {
    local line scheme hostport live rejected=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line//$'\r'/}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" =~ ^([Hh][Tt][Tt][Pp][Ss]?)://([^/?#]+) ]]; then
            scheme="${BASH_REMATCH[1],,}"
            hostport="${BASH_REMATCH[2],,}"
        else
            scheme=""
            hostport="${line%%[/?#]*}"
            hostport="${hostport,,}"
        fi
        if ! [[ "$hostport" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$ ]]; then
            rejected=$((rejected + 1))
            continue
        fi
        if [[ -z "$scheme" ]]; then
            live=$(awk -v h="$hostport" '$0 == "https://" h || $0 == "http://" h { print; exit }' \
                webs/webs_all.txt 2>/dev/null)
            printf '%s\n' "${live:-https://${hostport}}"
        else
            printf '%s://%s\n' "$scheme" "$hostport"
        fi
    done <"$1"
    ((rejected > 0)) && printf '[%s] newscan_checks: rejected %s malformed target line(s)\n' \
        "$(date +'%Y-%m-%d %H:%M:%S')" "$rejected" >>"$LOGFILE"
    return 0
}

function _newscan_fmt_dur() {
    local s="${1:-0}"
    ((s < 0)) && s=0
    if ((s >= 3600)); then
        printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
    elif ((s >= 60)); then
        printf '%dm' $((s / 60))
    else
        printf '%ds' "$s"
    fi
}

# NewScan's headless CLI prints no counts, only notices. Summarize one origin's console.log as
# "<latest phase>, <N> finding(s)[, <rate-limit state>]".
function _newscan_origin_status() {
    local log="$1" phase="starting" findings=0 rate="" line
    if [[ -s "$log" ]]; then
        line=$(grep -E 'Phase [0-9.]+ (—|-+) ' "$log" | tail -n 1 || true)
        if [[ -n "$line" ]]; then
            phase="${line#*Phase }"
            phase="Phase ${phase%%:*}"
            phase="${phase/ — / }"
            phase="${phase/ -- / }"
            phase="${phase/ - / }"
        fi
        findings=$(grep -c '\[FINDING\]' "$log" || true)
        line=$(grep -E 'Target is rate limiting|Rate limiting easing|Target stopped rate limiting' "$log" | tail -n 1 || true)
        if [[ "$line" == *"Target is rate limiting"* ]]; then
            rate="rate-limited"
            [[ "$line" =~ HTTP\ ([0-9]+) ]] && rate+=" (HTTP ${BASH_REMATCH[1]})"
            [[ "$line" =~ pacing\ requests\ ([0-9.]+)s ]] && rate+=", ${BASH_REMATCH[1]}s pacing"
        elif [[ "$line" =~ pace\ now\ ([0-9.]+)s ]]; then
            rate="easing, ${BASH_REMATCH[1]}s pacing"
        fi
    fi
    printf '%s, %s finding(s)%s\n' "$phase" "${findings:-0}" "${rate:+, $rate}"
}

# Whole-run ETA. After an origin finishes: elapsed / done * remaining (as lib/parallel.sh does
# for batches). Before that, the worst case allowed by the per-origin timeout, or "--".
function _newscan_eta() {
    local elapsed="$1" finished="$2" total="$3" max_par="$4" timeout="$5" bound
    if ((finished > 0)); then
        _newscan_fmt_dur $((elapsed * (total - finished) / finished))
    elif ((timeout > 0)); then
        bound=$(((total + max_par - 1) / max_par * (timeout + 60) - elapsed))
        printf 'max %s' "$(_newscan_fmt_dur "$bound")"
    else
        printf -- '--'
    fi
}

function _newscan_progress_line() {
    local origins="$1" launched="$2" total="$3" max_par="$4" elapsed="$5"
    local finished=0 n=0 origin slug active="" timeout="${NEWSCAN_TIMEOUT:-0}"
    [[ -z "${TIMEOUT_CMD:-}" ]] && timeout=0
    while IFS= read -r origin; do
        [[ -z "$origin" ]] && continue
        n=$((n + 1))
        ((n > launched)) && break
        slug=$(_newscan_slug "$origin")
        if [[ -f "vulns/newscan/${slug}/exit_code" ]]; then
            finished=$((finished + 1))
        else
            active+="; ${origin#*://}: $(_newscan_origin_status "vulns/newscan/${slug}/console.log")"
        fi
    done <"$origins"
    printf 'NewScan %s/%s done | elapsed %s | ETA %s%s\n' "$finished" "$total" "$(_newscan_fmt_dur "$elapsed")" \
        "$(_newscan_eta "$elapsed" "$finished" "$total" "$max_par" "$timeout")" "${active:+ |${active#;}}"
}

# Block until at most $1 scans are running, redrawing the live progress line every few seconds
# and appending it to $LOGFILE every NEWSCAN_PROGRESS_INTERVAL seconds. Polls instead of
# `wait -n` so progress keeps updating during multi-hour scans.
function _newscan_wait_running() {
    local keep="$1" origins="$2" launched="$3" total="$4" max_par="$5" start_ts="$6"
    local interval="${NEWSCAN_PROGRESS_INTERVAL:-300}" now line
    while (($(jobs -rp | wc -l) > keep)); do
        now=$(date +%s)
        if ((now - _NEWSCAN_LAST_DRAW >= 5)) || { ((interval > 0)) && ((now - _NEWSCAN_LAST_LOG >= interval)); }; then
            line=$(_newscan_progress_line "$origins" "$launched" "$total" "$max_par" $((now - start_ts)))
            declare -F ui_live_progress_update >/dev/null 2>&1 && ui_live_progress_update "$line"
            _NEWSCAN_LAST_DRAW=$now
            if ((interval > 0)) && ((now - _NEWSCAN_LAST_LOG >= interval)); then
                printf '[%s] newscan_checks progress: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$line" >>"$LOGFILE"
                _NEWSCAN_LAST_LOG=$now
            fi
        fi
        sleep 1
    done
}

function _newscan_scan_origin() {
    local origin="$1" idx="$2" image="$3"
    local out
    out="$dir/vulns/newscan/$(_newscan_slug "$origin")"
    mkdir -p "$out" || return 1
    out=$(cd "$out" && pwd -P) || return 1
    local cname="reconftw-newscan-$$-${idx}"

    local -a cmd=(docker run --rm --name "$cname" -v "${out}:/out")
    [[ -n "${NEWSCAN_ENV_FILE:-}" && -r "${NEWSCAN_ENV_FILE}" ]] && cmd+=(--env-file "$NEWSCAN_ENV_FILE")
    [[ "${NEWSCAN_USE_APP_CONFIG:-false}" == "true" ]] && cmd+=(-v "newscan-configs:/app/configs:ro")
    [[ -n "${NEWSCAN_DOCKER_NETWORK:-}" ]] && cmd+=(--network "$NEWSCAN_DOCKER_NETWORK")
    cmd+=("$image" python -m newscan "$origin"
        --scan-mode "${NEWSCAN_SCAN_MODE:-api}" --profile "${NEWSCAN_PROFILE:-quick}"
        --fail-on info --json /out/newscan.json --sarif /out/newscan.sarif --md /out/newscan.md)

    if [[ "${NEWSCAN_URL_SEED:-true}" == "true" && -s "$dir/webs/url_extract.txt" ]]; then
        awk -v o="$origin" 'index($0, o "/") == 1 || index($0, o "?") == 1 || $0 == o' \
            "$dir/webs/url_extract.txt" | head -n "${NEWSCAN_SEED_MAX:-2000}" >"$out/seed_urls.txt"
        [[ -s "$out/seed_urls.txt" ]] && cmd+=(--url-list /out/seed_urls.txt)
    fi
    ((${NEWSCAN_CONCURRENCY:-0} > 0)) && cmd+=(--concurrency "$NEWSCAN_CONCURRENCY")
    if [[ -n "${NEWSCAN_HEADERS:-}" ]]; then
        local -a _hdrs=()
        local _h
        IFS=';' read -ra _hdrs <<<"$NEWSCAN_HEADERS"
        for _h in "${_hdrs[@]}"; do
            [[ -n "${_h// /}" ]] && cmd+=(--header "$_h")
        done
    fi
    if [[ -n "${TIMEOUT_CMD:-}" ]] && ((${NEWSCAN_TIMEOUT:-0} > 0)); then
        cmd=("$TIMEOUT_CMD" -k 60 "${NEWSCAN_TIMEOUT}s" "${cmd[@]}")
    fi

    local rc=0
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        run_command "${cmd[@]}" || rc=$?
    else
        run_command "${cmd[@]}" >"$out/console.log" 2>&1 || rc=$?
    fi
    # Killing the docker client does not always stop the container; remove it explicitly.
    ((rc == 124 || rc == 137)) && docker rm -f "$cname" >/dev/null 2>&1
    printf '%s\n' "$rc" >"$out/exit_code"
    printf '[%s] newscan_checks: %s exit=%s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$origin" "$rc" >>"$LOGFILE"
    return 0
}

function newscan_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ ${NEWSCAN:-false} == true ]]; then

        local image="${NEWSCAN_IMAGE:-newscan:latest}"
        if [[ "${DRY_RUN:-false}" != "true" ]]; then
            if [[ "${PROXYCHAINS:-false}" == "true" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: PROXYCHAINS cannot route NewScan container traffic; skipping"
                return 0
            fi
            if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: docker not installed or daemon not running"
                return 0
            fi
            image=$(_newscan_resolve_image)
            if [[ -z "$image" ]] || ! docker image inspect "$image" >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: NewScan image '${image:-newscan:*}' not loaded (docker load -i newscan-image.tar)"
                return 0
            fi
        fi
        if [[ -n "${NEWSCAN_TARGETS_FILE:-}" ]] && [[ ! -f "$NEWSCAN_TARGETS_FILE" || ! -r "$NEWSCAN_TARGETS_FILE" ]]; then
            _print_msg WARN "${FUNCNAME[0]}: NEWSCAN_TARGETS_FILE not readable: ${NEWSCAN_TARGETS_FILE}"
            return 0
        fi

        start_func "${FUNCNAME[0]}" "NewScan API/web scanning"

        ensure_webs_all || true
        local origins=".tmp/newscan_origins.txt"
        _newscan_origins "${NEWSCAN_TARGETS_FILE:-webs/webs_all.txt}" | sort -u >"$origins"

        if [[ -n "${NEWSCAN_TARGETS_FILE:-}" && "${NEWSCAN_ENFORCE_SCOPE:-true}" == "true" &&
            "$domain" != "Multi" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            local _o _h
            while IFS= read -r _o; do
                _h="${_o#*://}"
                _h="${_h%%:*}"
                is_in_scope_host "$_h" "$domain" && printf '%s\n' "$_o"
            done <"$origins" >"${origins}.scoped"
            mv -f "${origins}.scoped" "$origins"
        fi
        [[ -n "${outOfScope_file:-}" ]] && deleteOutScoped "$outOfScope_file" "$origins"

        local max="${NEWSCAN_MAX_TARGETS:-25}"
        if [[ $DEEP != true ]] && ((max > 0)) && (($(wc -l <"$origins") > max)); then
            head -n "$max" "$origins" >"${origins}.capped" && mv -f "${origins}.capped" "$origins"
            _print_msg INFO "Limiting NewScan to ${max} origins (DEEP mode disabled)"
        fi
        if [[ ! -s "$origins" ]]; then
            end_func "No web origins to scan with NewScan" "${FUNCNAME[0]}" SKIP_NOINPUT
            return 0
        fi

        local max_par="${NEWSCAN_PARALLEL:-2}" idx=0 origin total start_ts
        ((max_par < 1)) && max_par=1
        total=$(wc -l <"$origins" | tr -d ' ')
        _print_msg INFO "Running: NewScan on ${total} origin(s)"
        # A leftover exit_code from an earlier run would count that origin as done in the progress line.
        while IFS= read -r origin; do
            rm -f "vulns/newscan/$(_newscan_slug "$origin")/exit_code"
        done <"$origins"
        start_ts=$(date +%s)
        _NEWSCAN_LAST_DRAW=0
        _NEWSCAN_LAST_LOG=0
        while IFS= read -r origin; do
            [[ -z "$origin" ]] && continue
            _newscan_wait_running $((max_par - 1)) "$origins" "$idx" "$total" "$max_par" "$start_ts" </dev/null
            idx=$((idx + 1))
            # Dry run stays in the foreground so run_command's dry-run tracking reaches the module summary.
            if [[ "${DRY_RUN:-false}" == "true" ]]; then
                _newscan_scan_origin "$origin" "$idx" "$image" </dev/null
            else
                _newscan_scan_origin "$origin" "$idx" "$image" </dev/null &
            fi
        done <"$origins"
        _newscan_wait_running 0 "$origins" "$idx" "$total" "$max_par" "$start_ts"
        wait
        declare -F ui_live_progress_end >/dev/null 2>&1 && ui_live_progress_end

        : >".tmp/newscan_findings.txt"
        : >".tmp/newscan_findings.jsonl"
        local failed=0 rc json
        while IFS= read -r origin; do
            json="vulns/newscan/$(_newscan_slug "$origin")/newscan.json"
            rc=$(cat "vulns/newscan/$(_newscan_slug "$origin")/exit_code" 2>/dev/null)
            [[ "${rc:-2}" == "0" || "${rc:-2}" == "1" ]] || failed=$((failed + 1))
            [[ -s "$json" ]] || continue
            jq -r --arg o "$origin" '.findings[]? | select((.ai_fp // false) | not)
                | "[\((.severity // "info") | ascii_upcase)] \($o) \(.where // "") - \(.title // "untitled") [\(.category // "")] (\(.confidence // (if .verified then "confirmed" else "tentative" end)))"' \
                "$json" >>".tmp/newscan_findings.txt" 2>>"$LOGFILE" || true
            jq -c --arg o "$origin" '.findings[]? | {type:"finding", tool:"newscan",
                severity:((.severity // "info") | ascii_downcase), name:(.title // ""),
                finding_type:(.category // ""), target:$o,
                host:($o | sub("^https?://"; "") | sub(":[0-9]+$"; "")), where:(.where // ""),
                verified:(.verified // false), confidence:(.confidence // ""),
                ai_false_positive:(.ai_fp // false), id:(.id // "")}' \
                "$json" >>".tmp/newscan_findings.jsonl" 2>>"$LOGFILE" || true
        done <"$origins"
        anew -q "vulns/newscan.txt" <".tmp/newscan_findings.txt"
        anew -q "vulns/newscan.jsonl" <".tmp/newscan_findings.jsonl"
        append_assets_from_file finding value "vulns/newscan.txt"

        ((failed > 0)) && notification "NewScan could not complete ${failed} origin(s); see vulns/newscan/*/console.log" warn
        local total hc
        total=$(sed '/^$/d' "vulns/newscan.txt" 2>/dev/null | wc -l | tr -d ' ')
        hc=$(grep -cE '^\[(HIGH|CRITICAL)\]' "vulns/newscan.txt" 2>/dev/null || true)
        end_func "${total:-0} NewScan findings (${hc:-0} high/critical) saved in vulns/newscan.txt" "${FUNCNAME[0]}"
    else
        if [[ ${NEWSCAN:-false} == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}
