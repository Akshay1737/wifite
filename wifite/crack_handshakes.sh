#!/usr/bin/env bash
#
# crack_handshakes.sh - Fast offline cracking of handshakes captured by wifite
#
# Converts every .cap handshake to hashcat 22000 format and runs an
# optimized attack ladder (wordlist -> rules -> escalating GPU masks),
# fastest attacks first.
#
# Usage:
#   ./crack_handshakes.sh                     # auto-detect hs/, rockyou
#   ./crack_handshakes.sh -w mylist.txt       # custom wordlist
#   ./crack_handshakes.sh -d ~/hs             # custom handshake dir
#   ./crack_handshakes.sh --aggressive        # add slow masks (strong GPU)
#   ./crack_handshakes.sh --benchmark         # hashcat speed only
#
# AUTHORIZED TESTING ONLY - networks you own or have permission to audit.
#
set -euo pipefail

HS_DIR="hs"
WORDLIST=""
AGGRESSIVE=0
BENCHMARK=0
CONVERT_DIR=""
RULES=""
POTFILE=""

c_green() { printf '\033[1;32m%s\033[0m\n' "$1"; }
c_red()   { printf '\033[1;31m%s\033[0m\n' "$1"; }
c_yell()  { printf '\033[1;33m%s\033[0m\n' "$1"; }
c_cyan()  { printf '\033[1;36m%s\033[0m\n' "$1"; }

usage() {
    grep '^#' "$0" | head -n 18 | sed 's/^# \{0,2\}//'
    exit 0
}

need() {
    command -v "$1" >/dev/null 2>&1 || { c_red "[!] Missing dependency: $1"; exit 1; }
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) HS_DIR="$2"; shift 2 ;;
        -w) WORDLIST="$2"; shift 2 ;;
        --aggressive) AGGRESSIVE=1; shift ;;
        --benchmark)  BENCHMARK=1; shift ;;
        -h|--help) usage ;;
        *) c_red "[!] Unknown option: $1"; usage ;;
    esac
done

need hashcat
need hcxpcapngtool
[[ -d "$HS_DIR" ]] || { c_red "[!] Handshake directory not found: $HS_DIR"; exit 1; }

CONVERT_DIR="$HS_DIR/.converted"
mkdir -p "$CONVERT_DIR"
POTFILE="$CONVERT_DIR/wifite.pot"

convert_all() {
    local count=0 cap base out
    shopt -s nullglob
    for cap in "$HS_DIR"/*.cap; do
        base="$(basename "$cap" .cap)"
        out="$CONVERT_DIR/$base.22000"
        if [[ -s "$out" && "$out" -nt "$cap" ]]; then
            continue   # cached conversion is up-to-date
        fi
        c_cyan "[*] Converting $(basename "$cap") ..."
        if hcxpcapngtool -o "$out" "$cap" >/dev/null 2>&1 && [[ -s "$out" ]]; then
            count=$((count+1))
        else
            rm -f "$out"
            c_yell "    no convertible hashes in this capture"
        fi
    done
    shopt -u nullglob
    c_green "[+] Conversion done ($count new)."
}

HASH_FILES=()
collect_hashes() {
    shopt -s nullglob
    for f in "$HS_DIR"/*.22000 "$CONVERT_DIR"/*.22000; do
        HASH_FILES+=("$f")
    done
    shopt -u nullglob
    if [[ ${#HASH_FILES[@]} -eq 0 ]]; then
        c_red "[!] No hashes found in '$HS_DIR'. Capture some first."
        exit 1
    fi
    c_green "[+] ${#HASH_FILES[@]} hash file(s) queued:"
    printf '      %s\n' "${HASH_FILES[@]}"
}

find_wordlist() {
    [[ -n "$WORDLIST" ]] && return
    local cand
    for cand in \
        /usr/share/wordlists/rockyou.txt \
        /usr/share/wordlists/rockyou.txt.gz \
        "$HOME/wordlists/rockyou.txt" \
        /opt/wordlists/rockyou.txt; do
        if [[ -f "$cand" ]]; then WORDLIST="$cand"; break; fi
    done
    if [[ -z "$WORDLIST" ]]; then
        c_yell "[!] No default wordlist found - pass one with: -w /path/to/list"
    else
        c_green "[+] Wordlist: $WORDLIST"
    fi
}

find_rules() {
    local cand
    for cand in \
        /usr/share/hashcat/rules/best64.rule \
        /usr/share/hashcat/rules/best64.rules \
        /usr/local/share/hashcat/rules/best64.rule; do
        [[ -f "$cand" ]] && { RULES="$cand"; return; }
    done
}

hc() {
    # hc <extra args...> ; hash files appended from HASH_FILES
    local -a cmd=(hashcat --quiet -m 22000 --potfile-path "$POTFILE")
    if ! hashcat -I >/dev/null 2>&1 || hashcat -I 2>&1 | grep -qi 'No devices found'; then
        cmd+=(--force)   # CPU-only / flaky OpenCL fallback
    fi
    cmd+=("$@")
    cmd+=("${HASH_FILES[@]}")
    "${cmd[@]}" || true
}

check_pot() {
    [[ -s "$POTFILE" ]] || return 1
    local cracked=0 line pass
    while IFS= read -r line; do
        pass="${line##*:}"
        [[ -n "$pass" ]] || continue
        c_green "[+] CRACKED: $pass"
        cracked=$((cracked+1))
    done < "$POTFILE"
    (( cracked > 0 ))
}

finish() {
    local elapsed=$(( $(date +%s) - $1 ))
    c_green "[OK] Finished in ${elapsed}s."
}

run_ladder() {
    local started
    started=$(date +%s)

    c_cyan "[*] Stage 0: potfile reuse ..."
    check_pot || true

    if [[ -n "$WORDLIST" ]]; then
        c_cyan "[*] Stage 1: dictionary ($WORDLIST)"
        hc "$WORDLIST"
        check_pot && { finish "$started"; return 0; } || true

        if [[ -n "$RULES" ]]; then
            c_cyan "[*] Stage 2: dictionary + rules ($RULES)"
            hc -r "$RULES" "$WORDLIST"
            check_pot && { finish "$started"; return 0; } || true
        fi
    else
        c_yell "[*] Skipping dictionary stages (no wordlist)."
    fi

    c_cyan "[*] Stage 3: mask brute-force ladder (fast keyspaces first)"
    local -a masks=(
        '?d?d?d?d?d?d?d?d'
        '?d?d?d?d?d?d?d?d?d'
        '?l?l?l?l?l?l?l?l'
    )
    (( AGGRESSIVE )) && masks+=(
        '?d?d?d?d?d?d?d?d?d?d'
        '?l?u?d?l?u?d?l?u'
        '?a?a?a?a?a?a?a'
    )
    local m
    for m in "${masks[@]}"; do
        c_cyan "    mask: $m"
        hc "$m"
        check_pot && { finish "$started"; return 0; } || true
    done

    finish "$started"
    c_red "[!] Ladder exhausted without a crack."
    c_yell "    Try a bigger wordlist (-w), more rules, or longer custom masks."
}

echo "==============================================================="
echo " wifite handshake cracker - AUTHORIZED USE ONLY"
echo "==============================================================="

convert_all
collect_hashes
find_wordlist
find_rules

if [[ $BENCHMARK -eq 1 ]]; then
    hashcat -b -m 22000 --potfile-path "$POTFILE" || true
    exit 0
fi
run_ladder