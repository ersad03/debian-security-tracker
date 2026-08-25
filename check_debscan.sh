#!/usr/bin/env bash

# Nagios wrapper: runs debsecan and returns OK, CRITICAL or UNKNOWN.
#
# Sudoers configuration (edit with visudo):
# Cmnd alias specification
# Cmnd_Alias CHECK_DEBSCAN=/usr/local/bin/debsecan_cve_scores.sh
# User privilege specification
# nagios  ALL=(ALL) NOPASSWD : CHECK_DEBSCAN
#
# NRPE line:
#   command[check_debscan]=/usr/local/share/nagios/plugins/check_debscan.sh --cve-score 9.0 --jobs 8 --only-active
# Apply: systemctl restart nagios-nrpe-server
#
# Defaults (command-line options override them):
SCORE="9.0"
JOBS="8"
MODE="--only-active"
DEBSECAN_SCRIPT="/usr/local/bin/debsecan_cve_scores.sh"

usage() {
    echo "Usage: $0 [--cve-score NUMBER] [--jobs NUMBER] [--only-active|--only-obsolete|--all]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cve-score)
            if [[ $# -lt 2 ]]; then
                echo "UNKNOWN - missing value for $1"
                exit 3
            fi
            SCORE="$2"
            shift 2
            ;;
        --jobs)
            if [[ $# -lt 2 ]]; then
                echo "UNKNOWN - missing value for --jobs"
                exit 3
            fi
            JOBS="$2"
            shift 2
            ;;
        --only-active|--only-obsolete|--all)
            MODE="$1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "UNKNOWN - invalid option: $1"
            usage
            exit 3
            ;;
    esac
done

if ! [[ "$SCORE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "UNKNOWN - score must be a number"
    exit 3
fi

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "UNKNOWN - jobs must be a positive integer"
    exit 3
fi

case "$MODE" in
    --only-active) SCOPE="active" ;;
    --only-obsolete) SCOPE="obsolete" ;;
    --all) SCOPE="active or obsolete" ;;
esac

output=$(sudo -n "$DEBSECAN_SCRIPT" \
    --cve-score "$SCORE" \
    --jobs "$JOBS" \
    "$MODE" 2>&1)
result=$?

if [[ $result -ne 0 ]]; then
    printf 'UNKNOWN - debsecan check failed\n%s\n' "$output"
    exit 3
fi

if grep -q "NO NEW RECORDS FOUND" <<< "$output"; then
    printf 'OK - no %s CVEs above score %s (0 critical packages)\n' "$SCOPE" "$SCORE"
    exit 0
fi

# Ignore vulnerable kernel packages whose version is older than the running
# kernel: leftover linux-image/linux-headers packages are not in use. The
# running kernel itself and any newer, not-yet-booted kernel still count.
running_kernel=$(uname -r)

is_superseded_kernel_pkg() {
    local pkg="$1"
    [[ "$pkg" =~ ^linux-(image|headers)-([0-9][^[:space:]]*)$ ]] || return 1
    dpkg --compare-versions "${BASH_REMATCH[2]}" lt "$running_kernel" 2>/dev/null
}

filtered_output=""
ignored_count=0
while IFS= read -r line; do
    read -r cve _ _ pkg _ <<< "$line"
    if [[ "$cve" == CVE-* ]] && is_superseded_kernel_pkg "$pkg"; then
        ignored_count=$((ignored_count + 1))
        continue
    fi
    filtered_output+="${line}"$'\n'
done <<< "$output"

package_count=$(
    awk '$1 ~ /^CVE-/ { print $4 }' <<< "$filtered_output" |
        sort -u |
        wc -l
)

if [[ $package_count -eq 0 ]]; then
    if [[ $ignored_count -gt 0 ]]; then
        printf 'OK - no %s CVEs above score %s (0 critical packages, %d CVEs on superseded kernels ignored)\n' \
            "$SCOPE" "$SCORE" "$ignored_count"
        exit 0
    fi
    # No CVEs, no ignored kernels, but also no "NO NEW RECORDS FOUND" marker:
    # the output is unrecognized, so surface it instead of reporting OK.
    printf 'UNKNOWN - unrecognized debsecan output\n%s\n' "$output"
    exit 3
fi

if [[ $ignored_count -gt 0 ]]; then
    printf 'WARNING - %s CVEs above score %s found (%d critical packages, %d CVEs on superseded kernels ignored)\n' \
        "$SCOPE" "$SCORE" "$package_count" "$ignored_count"
else
    printf 'WARNING - %s CVEs above score %s found (%d critical packages)\n' \
        "$SCOPE" "$SCORE" "$package_count"
fi
printf '%s' "$filtered_output"
exit 1

# Use `exit 1` for WARNING Nagios alerts and `exit 2` for CRITICAL Nagios alerts.
