#!/usr/bin/env bash
set -euo pipefail

DSA_URL="https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list"
JOBS="${JOBS:-5}"
CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-10}"
CURL_MAX_TIME="${CURL_MAX_TIME:-60}"
CURL_RETRIES="${CURL_RETRIES:-3}"
CURL_RETRY_DELAY="${CURL_RETRY_DELAY:-5}"
STATE_FILE="/run/dsa_new_cve_scores.state"
if ! { [[ -e "$STATE_FILE" && -w "$STATE_FILE" ]] || [[ ! -e "$STATE_FILE" && -w /run ]]; }; then
  STATE_FILE="/run/user/${UID}/dsa_new_cve_scores/state"
  mkdir -p "$(dirname "$STATE_FILE")"
fi

SEARCH_DSA_ARGS=()

usage() {
  cat <<'USAGE'
Usage: dsa_new_cve_scores.sh [OPTIONS]

Track new Debian Security Advisories and print CVE scores.

Options:
  -h, --help                 Show this help and exit
  --jobs N                   Parallel CVE API requests (default: 5)
  --search-dsa LIST          Search specific DSA(s); separators: comma, semicolon, or space

Notes:
  - Normal mode uses state file under /run and processes only new DSA entries
  - First run processes only latest 3 DSA records
  - Search mode ignores state and prints results only for requested DSA(s)

Examples:
  dsa_new_cve_scores.sh --search-dsa DSA-6261-1 DSA6263-1
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --search-dsa)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --search-dsa" >&2
        exit 2
      fi
      while [[ $# -gt 0 && "$1" != -* ]]; do
        SEARCH_DSA_ARGS+=("$1")
        shift
      done
      ;;
    --search-dsa=*)
      SEARCH_DSA_ARGS+=("${1#*=}")
      shift
      ;;
    --jobs)
      shift
      if [[ $# -eq 0 ]]; then
        echo "Missing value for --jobs" >&2
        exit 2
      fi
      JOBS="$1"
      shift
      ;;
    --jobs=*)
      JOBS="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Use --help for usage." >&2
      exit 2
      ;;
  esac
done

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "Invalid --jobs value: $JOBS (must be integer >= 1)" >&2
  exit 2
fi

TMP_LIST="$(mktemp)"
TMP_PARSED="$(mktemp)"
TMP_NEW="$(mktemp)"
OUT_RAW="$(mktemp)"
OUT_DSA_CVES="$(mktemp)"
SEARCH_TOKENS="$(mktemp)"
SEARCH_WANTED="$(mktemp)"
UNIQUE_CVES="$(mktemp)"
SCORES_TSV="$(mktemp)"
trap 'rm -f "$TMP_LIST" "$TMP_PARSED" "$TMP_NEW" "$OUT_RAW" "$OUT_DSA_CVES" "$SEARCH_TOKENS" "$SEARCH_WANTED" "$UNIQUE_CVES" "$SCORES_TSV"' EXIT

for cmd in curl awk sed grep column jq sort tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

canonicalize_dsa() {
  local raw="$1"
  local x
  x="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -n "$x" ]] || return 1

  if [[ "$x" =~ ^DSA-[0-9]+-[0-9]+$ ]]; then
    printf '%s\n' "$x"
    return 0
  fi
  if [[ "$x" =~ ^[0-9]+-[0-9]+$ ]]; then
    printf 'DSA-%s\n' "$x"
    return 0
  fi
  if [[ "$x" =~ ^DSA[0-9]+-[0-9]+$ ]]; then
    printf 'DSA-%s\n' "${x#DSA}"
    return 0
  fi

  return 1
}

fetch_one() {
  local cve="$1"
  local body score http_code curl_exit

  # Do not use -f here; we need HTTP status to classify outcomes accurately.
  body="$(curl -sS \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --retry "$CURL_RETRIES" \
    --retry-delay "$CURL_RETRY_DELAY" \
    --retry-all-errors \
    -w $'\n%{http_code}' \
    "https://cveawg.mitre.org/api/cve/$cve" 2>/dev/null)" || curl_exit=$?
  curl_exit="${curl_exit:-0}"
  if (( curl_exit != 0 )); then
    printf '%s\tN/A\t1\ttransport_error\n' "$cve"
    return
  fi

  http_code="$(printf '%s\n' "$body" | tail -n1)"
  body="$(printf '%s\n' "$body" | sed '$d')"

  if [[ ! "$http_code" =~ ^[0-9]{3}$ ]]; then
    printf '%s\tN/A\t1\tinvalid_http_code\n' "$cve"
    return
  fi

  if [[ "$http_code" == "404" ]]; then
    # CVE not found / not yet published in this API: not a failed call.
    printf '%s\tN/A\t0\tnot_found\n' "$cve"
    return
  fi

  if [[ "$http_code" != "200" ]]; then
    # Treat server-side errors as failed calls; other non-200 are informational.
    if (( http_code >= 500 )); then
      printf '%s\tN/A\t1\thttp_%s\n' "$cve" "$http_code"
    else
      printf '%s\tN/A\t0\thttp_%s\n' "$cve" "$http_code"
    fi
    return
  fi

  if ! score="$(printf '%s' "$body" | jq -r '[..|objects|.cvssV4_0?.baseScore?, .cvssV3_1?.baseScore?, .cvssV3_0?.baseScore?, .cvssV2_0?.baseScore?] | map(select(.!=null)) | .[0] // "N/A"' 2>/dev/null)"; then
    printf '%s\tN/A\t1\tparse_error\n' "$cve"
    return
  fi

  [[ -n "$score" ]] || score="N/A"
  printf '%s\t%s\t0\tok\n' "$cve" "$score"
}
export -f fetch_one
export CURL_CONNECT_TIMEOUT CURL_MAX_TIME CURL_RETRIES CURL_RETRY_DELAY

if ! curl -fsS \
  --connect-timeout "$CURL_CONNECT_TIMEOUT" \
  --max-time "$CURL_MAX_TIME" \
  --retry "$CURL_RETRIES" \
  --retry-delay "$CURL_RETRY_DELAY" \
  --retry-all-errors \
  "$DSA_URL" \
  -o "$TMP_LIST" 2>/dev/null; then
  echo "~~~~ NO NEW RECORDS FOUND ~~~~"
  exit 0
fi

awk '
BEGIN { OFS="\t"; seq=0; dsa=""; date=""; pkg=""; cves=""; releases="" }

function flush_record() {
  if (dsa != "" && pkg != "") {
    seq++
    print seq, dsa, date, pkg, cves, releases
  }
}

/^\[[^]]+\][[:space:]]+DSA-[0-9]+-[0-9]+[[:space:]]+/ {
  flush_record()
  line=$0
  date=""; dsa=""; pkg=""; cves=""; releases=""

  if (match(line, /^\[([^]]+)\]/, m)) date=m[1]
  if (match(line, /(DSA-[0-9]+-[0-9]+)/, m2)) dsa=m2[1]

  h=line
  sub(/^\[[^]]+\][[:space:]]+/, "", h)
  sub(/^DSA-[0-9]+-[0-9]+[[:space:]]+/, "", h)
  sub(/[[:space:]]+-[[:space:]].*$/, "", h)
  pkg=h
  next
}

{
  if (dsa == "") next
  line=$0
  gsub(/^[[:space:]]+/, "", line)

  if (line ~ /^\{.*\}$/) {
    c=line
    gsub(/[{}]/, "", c)
    gsub(/[[:space:]]+/, " ", c)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", c)
    cves=c
    next
  }

  if (line ~ /^\[[^]]+\][[:space:]]+-[[:space:]]+/) {
    rel=line
    sub(/^\[/, "", rel)
    sub(/\][[:space:]]+-[[:space:]]+/, ":", rel)
    if (releases == "") releases=rel
    else releases=releases" | "rel
  }
}

END { flush_record() }
' "$TMP_LIST" > "$TMP_PARSED"

if [[ ! -s "$TMP_PARSED" ]]; then
  echo "~~~~ NO NEW RECORDS FOUND ~~~~"
  exit 0
fi

if [[ ${#SEARCH_DSA_ARGS[@]} -gt 0 ]]; then
  printf '%s\n' "${SEARCH_DSA_ARGS[@]}" \
    | tr ',;' '\n\n' \
    | tr '[:space:]' '\n' \
    | sed '/^$/d' > "$SEARCH_TOKENS"

  : > "$SEARCH_WANTED"
  while IFS= read -r token; do
    canon="$(canonicalize_dsa "$token" || true)"
    [[ -n "$canon" ]] && printf '%s\n' "$canon" >> "$SEARCH_WANTED"
  done < "$SEARCH_TOKENS"

  sort -u "$SEARCH_WANTED" -o "$SEARCH_WANTED"

  if [[ ! -s "$SEARCH_WANTED" ]]; then
    echo "No valid DSA identifiers in --search-dsa input." >&2
    exit 2
  fi

  awk -F '\t' 'NR==FNR { want[$1]=1; next } ($2 in want) { print }' "$SEARCH_WANTED" "$TMP_PARSED" > "$TMP_NEW"
else
  if [[ ! -f "$STATE_FILE" ]]; then
    head -n 3 "$TMP_PARSED" > "$TMP_NEW"
    latest_dsa="$(awk -F '\t' 'NR==1{print $2}' "$TMP_PARSED")"
    printf 'last_dsa=%s\n' "$latest_dsa" > "$STATE_FILE"
  else
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    if [[ -z "${last_dsa:-}" ]]; then
      head -n 3 "$TMP_PARSED" > "$TMP_NEW"
    else
      awk -F '\t' -v last="$last_dsa" '
        $2==last { found=1; exit }
        { print }
        END { if (!found) exit 2 }
      ' "$TMP_PARSED" > "$TMP_NEW" || {
        # Cursor disappeared upstream; re-seed conservatively.
        head -n 3 "$TMP_PARSED" > "$TMP_NEW"
      }
    fi
    latest_dsa="$(awk -F '\t' 'NR==1{print $2}' "$TMP_PARSED")"
    if [[ -n "$latest_dsa" ]]; then
      printf 'last_dsa=%s\n' "$latest_dsa" > "$STATE_FILE"
    fi
  fi
fi

if [[ ! -s "$TMP_NEW" ]]; then
  echo "~~~~ NO NEW RECORDS FOUND ~~~~"
  exit 0
fi

awk -F '\t' '
{
  if ($5 == "") next
  n=split($5, a, /[[:space:]]+/)
  for (i=1; i<=n; i++) {
    if (a[i] ~ /^CVE-[0-9]{4}-[0-9]+$/) print a[i]
  }
}
' "$TMP_NEW" | sort -u > "$UNIQUE_CVES"

if [[ ! -s "$UNIQUE_CVES" ]]; then
  echo "~~~~ NO NEW RECORDS FOUND ~~~~"
  exit 0
fi

xargs -r -n1 -P "$JOBS" bash -lc 'fetch_one "$0"' < "$UNIQUE_CVES" > "$SCORES_TSV"

declare -A CVE_SCORE
while IFS=$'\t' read -r cve score _failed _reason; do
  [[ -n "$cve" ]] || continue
  CVE_SCORE["$cve"]="$score"
done < "$SCORES_TSV"

while IFS=$'\t' read -r _seq dsa _date pkg cves releases; do
  [[ -n "$cves" ]] || continue
  : > "$OUT_DSA_CVES"

  for cve in $cves; do
    [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]+$ ]] || continue
    score="${CVE_SCORE[$cve]:-N/A}"
    if [[ "$score" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      sort_score="$score"
    else
      sort_score="-1"
    fi
    printf '%s\t%s\t%s\n' "$sort_score" "$cve" "$score" >> "$OUT_DSA_CVES"
  done

  sort -t $'\t' -k1,1nr -k2,2 "$OUT_DSA_CVES" | while IFS=$'\t' read -r _sort_score cve score; do
    printf '%s;%s;%s;%s;%s\n' "$dsa" "$cve" "$score" "$pkg" "$releases" >> "$OUT_RAW"
  done
done < "$TMP_NEW"

if [[ ! -s "$OUT_RAW" ]]; then
  failed_count="$(awk -F '\t' '$3=="1"{n++} END{print n+0}' "$SCORES_TSV")"
  printf '~~~~ [API] failed calls: %s ~~~~\n' "$failed_count"
  echo "~~~~ NO NEW RECORDS FOUND ~~~~"
  exit 0
fi

column -s ';' -t "$OUT_RAW"
failed_count="$(awk -F '\t' '$3=="1"{n++} END{print n+0}' "$SCORES_TSV")"
printf '~~~~ [API] failed calls: %s ~~~~\n' "$failed_count"
