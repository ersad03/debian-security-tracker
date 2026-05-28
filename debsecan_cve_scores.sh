#!/usr/bin/env bash
set -euo pipefail

#################################
###       Version 1.0.0       ###
#################################

SUITE="$(lsb_release -sc)"
MIN_SCORE="7.5"
MODE="all"
MODE_SET="0"
STATS_MODE="0"
SEARCH_PACKAGE=""
RUNDIR_BASE="/run/active_cve_scores"
JOBS="${JOBS:-6}"
OUTPUT_FILE="$RUNDIR_BASE/debsecan_cve_scores.tsv"

usage() {
  cat <<'USAGE'
Usage: debsecan_cve_scores.sh [OPTIONS]

Collect CVEs from debsecan (--only-fixed), enrich with CVSS score from CVE API,
filter by score threshold, and print/write sorted results.

Options:
  -h, --help                Show this help and exit
  --cve-score VALUE, --cve-score=VALUE  CVSS threshold (print score > VALUE; default: 7.5)
  --jobs N                              Parallel CVE API requests (default: 6)
  --all                                 Include active and obsolete (default)
  --only-active                         Include only active entries
  --only-obsolete                       Include only obsolete entries
  --search-package NAME                 Search CVEs for a specific binary package

Stats Mode:
  --stats                               Print per package/source stats (TOTAL/ACTIVE/OBSOLETE)
                                        Can be combined with: --all / --only-active / --only-obsolete
                                        Cannot be combined with: --cve-score, --jobs, --search-package

Search Mode:
  --search-package NAME                 Uses debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail as source
                                        Matches against source and binary package names
                                        Default status filter: --all
                                        Can be overridden with: --only-active / --only-obsolete / --all
                                        Cannot be combined with: --stats

Output:
  Normal/stats mode: printed to stdout and written to
    /run/active_cve_scores/debsecan_cve_scores.tsv
USAGE
}

score_or_jobs_set=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --cve-score)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --cve-score" >&2
        exit 2
      fi
      MIN_SCORE="$2"
      score_or_jobs_set=1
      shift 2
      ;;
    --cve-score=*)
      MIN_SCORE="${1#*=}"
      score_or_jobs_set=1
      shift
      ;;
    --jobs)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --jobs" >&2
        exit 2
      fi
      JOBS="$2"
      score_or_jobs_set=1
      shift 2
      ;;
    --jobs=*)
      JOBS="${1#*=}"
      score_or_jobs_set=1
      shift
      ;;
    --all)
      MODE="all"
      MODE_SET="1"
      shift
      ;;
    --only-active)
      MODE="active"
      MODE_SET="1"
      shift
      ;;
    --only-obsolete)
      MODE="obsolete"
      MODE_SET="1"
      shift
      ;;
    --stats)
      STATS_MODE="1"
      shift
      ;;
    --search-package)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --search-package" >&2
        exit 2
      fi
      SEARCH_PACKAGE="$2"
      shift 2
      ;;
    --search-package=*)
      SEARCH_PACKAGE="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Use --help for usage." >&2
      exit 2
      ;;
  esac
done

if [[ "$STATS_MODE" == "1" && "$score_or_jobs_set" == "1" ]]; then
  echo "--stats cannot be used with --cve-score or --jobs." >&2
  exit 2
fi

if [[ -n "$SEARCH_PACKAGE" && "$STATS_MODE" == "1" ]]; then
  echo "--search-package cannot be used with --stats." >&2
  exit 2
fi

if ! [[ "$MIN_SCORE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "Invalid --cve-score value: $MIN_SCORE" >&2
  exit 2
fi

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "Invalid --jobs value: $JOBS (must be integer >= 1)" >&2
  exit 2
fi

if ! command -v debsecan >/dev/null 2>&1; then
  echo "debsecan is required but not installed." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not installed." >&2
  exit 1
fi

fetch_one() {
  local cve="$1"
  local body
  local score
  if ! body=$(curl -fsS --max-time 20 "https://cveawg.mitre.org/api/cve/$cve" 2>/dev/null); then
    printf '%s\tN/A\t1\n' "$cve"
    return
  fi
  if ! score=$(printf '%s' "$body" | jq -r '[..|objects|.cvssV4_0?.baseScore?, .cvssV3_1?.baseScore?, .cvssV3_0?.baseScore?, .cvssV2_0?.baseScore?] | map(select(.!=null)) | .[0] // "N/A"' 2>/dev/null); then
    printf '%s\tN/A\t1\n' "$cve"
    return
  fi
  printf '%s\t%s\t0\n' "$cve" "$score"
}
export -f fetch_one

# Search mode: stdout only, no file output.
if [[ -n "$SEARCH_PACKAGE" ]]; then
  # default search filter is all unless explicitly overridden
  if [[ "$MODE_SET" == "0" ]]; then
    MODE="all"
  fi

  mkdir -p "$RUNDIR_BASE"
  workdir="$RUNDIR_BASE/search_run"
  rm -rf "$workdir"
  mkdir -p "$workdir"
  trap 'rm -rf "$workdir"' EXIT

  pairs_tsv="$workdir/pairs.tsv"
  selected_pairs_tsv="$workdir/selected_pairs.tsv"
  selected_match_pairs="$workdir/selected_match_pairs.tsv"
  selected_cves="$workdir/selected_cves.txt"
  scores_tsv="$workdir/scores.tsv"
  result_tsv="$workdir/result.tsv"

  # Parse detail output once into file-based records, same model as normal mode.
  debsecan --suite "$SUITE" --only-fixed --format detail \
  | awk '
      BEGIN { RS=""; FS="\n" }
      {
        cve=""; pkg=""; src=""; obsolete="active"
        if (match($0, /^CVE-[0-9][0-9][0-9][0-9]-[0-9]+/)) cve=substr($0, RSTART, RLENGTH)
        for (i=1; i<=NF; i++) {
          if ($i ~ /^[[:space:]]+installed:/) {
            line=$i
            sub(/^[[:space:]]+installed:[[:space:]]+/, "", line)
            pkg=line
            sub(/[[:space:]].*$/, "", pkg)
          }
          if ($i ~ /\(built from /) {
            line=$i
            sub(/^.*\(built from[[:space:]]+/, "", line)
            sub(/[[:space:]]+[0-9].*\)$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            src=line
          }
          if ($i ~ /package is obsolete/) obsolete="obsolete"
        }
        if (src == "") src=pkg
        if (cve != "" && src != "" && pkg != "") {
          print cve "\t" src "\t" pkg "\t" obsolete
        }
      }
    ' | sort -u > "$pairs_tsv"

  case "$MODE" in
    active)
      awk -F '\t' '$4=="active"' "$pairs_tsv" > "$selected_pairs_tsv"
      ;;
    obsolete)
      awk -F '\t' '$4=="obsolete"' "$pairs_tsv" > "$selected_pairs_tsv"
      ;;
    all)
      cp "$pairs_tsv" "$selected_pairs_tsv"
      ;;
    *)
      echo "Invalid mode: $MODE" >&2
      exit 2
      ;;
  esac

  awk -F '\t' -v q="$SEARCH_PACKAGE" '
    BEGIN {
      q_lc = tolower(q)
      use_glob = (index(q_lc, "*") > 0 || index(q_lc, "?") > 0)
      if (use_glob) {
        pat = q_lc
        gsub(/\\/,"\\\\", pat)
        gsub(/\./,"\\.", pat)
        gsub(/\+/,"\\+", pat)
        gsub(/\(/,"\\(", pat)
        gsub(/\)/,"\\)", pat)
        gsub(/\[/,"\\[", pat)
        gsub(/\]/,"\\]", pat)
        gsub(/\^/,"\\^", pat)
        gsub(/\$/,"\\$", pat)
        gsub(/\{/,"\\{", pat)
        gsub(/\}/,"\\}", pat)
        gsub(/\|/,"\\|", pat)
        gsub(/\*/,".*", pat)
        gsub(/\?/,".", pat)
        re = "^" pat "$"
      }
    }
    function matches(t,    tl) {
      tl = tolower(t)
      if (use_glob) return (tl ~ re)
      return (index(tl, q_lc) > 0)
    }
    (matches($2) || matches($3)) { print }
  ' "$selected_pairs_tsv" | sort -u > "$selected_match_pairs"

  cut -f1 "$selected_match_pairs" | sort -u > "$selected_cves"

  if [[ ! -s "$selected_cves" ]]; then
    printf '~~~~ [API] failed calls: 0 ~~~~\n'
    printf '~~~~ NO NEW RECORDS FOUND ~~~~\n'
    exit 0
  fi

  xargs -r -n1 -P "$JOBS" bash -lc 'fetch_one "$0"' < "$selected_cves" > "$scores_tsv"

  awk -F '\t' -v min_score="$MIN_SCORE" '
    NR==FNR { score[$1]=$2; next }
    {
      s = (($1 in score) ? score[$1] : "N/A")
      if (s == "N/A") next
      if ((s + 0) <= (min_score + 0)) next
      printf "%s\t%s\t%s\t%s\n", $1, s, $2, $3
    }
  ' "$scores_tsv" "$selected_match_pairs" | LC_ALL=C sort -t $'\t' -k2,2gr -k1,1 -k3,3 -k4,4 > "$result_tsv"

  cat "$result_tsv"
  failed_count=$(awk -F '\t' '$3=="1"{n++} END{print n+0}' "$scores_tsv")
  printf '~~~~ [API] failed calls: %s ~~~~\n' "$failed_count"
  if [[ ! -s "$result_tsv" ]]; then
    printf '~~~~ NO NEW RECORDS FOUND ~~~~\n'
  fi
  exit 0
fi

mkdir -p "$RUNDIR_BASE"
: > "$OUTPUT_FILE"

workdir=$(mktemp -d "$RUNDIR_BASE/run.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

pairs_tsv="$workdir/pairs.tsv"
selected_pairs_tsv="$workdir/selected_pairs.tsv"
unique_cves="$workdir/unique_cves.txt"
scores_tsv="$workdir/scores.tsv"
result_tsv="$workdir/result.tsv"

# Parse debsecan detail output once.
# Output columns: CVE<TAB>Source<TAB>BinaryPackage<TAB>ObsoleteFlag
debsecan --suite "$SUITE" --only-fixed --format detail \
| awk '
BEGIN { RS=""; FS="\n" }
{
  cve=""
  pkg=""
  src=""
  obsolete="active"

  if (match($0, /^CVE-[0-9][0-9][0-9][0-9]-[0-9]+/)) {
    cve=substr($0, RSTART, RLENGTH)
  }

  for (i=1; i<=NF; i++) {
    if ($i ~ /^[[:space:]]+installed:/) {
      line=$i
      sub(/^[[:space:]]+installed:[[:space:]]+/, "", line)
      pkg=line
      sub(/[[:space:]].*$/, "", pkg)
    }

    if ($i ~ /\(built from /) {
      line=$i
      sub(/^.*\(built from[[:space:]]+/, "", line)
      sub(/[[:space:]]+[0-9].*\)$/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      src=line
    }

    if ($i ~ /package is obsolete/) {
      obsolete="obsolete"
    }
  }

  if (src == "") src=pkg
  if (cve != "" && src != "" && pkg != "") {
    print cve "\t" src "\t" pkg "\t" obsolete
  }
}
' | sort -u > "$pairs_tsv"

if [[ ! -s "$pairs_tsv" ]]; then
  if [[ "$STATS_MODE" != "1" ]]; then
    printf '~~~~ [API] failed calls: 0 ~~~~\n'
    printf '~~~~ NO NEW RECORDS FOUND ~~~~\n'
  fi
  exit 0
fi

case "$MODE" in
  active)
    awk -F '\t' '$4=="active"' "$pairs_tsv" > "$selected_pairs_tsv"
    ;;
  obsolete)
    awk -F '\t' '$4=="obsolete"' "$pairs_tsv" > "$selected_pairs_tsv"
    ;;
  all)
    cp "$pairs_tsv" "$selected_pairs_tsv"
    ;;
  *)
    echo "Invalid mode: $MODE" >&2
    exit 2
    ;;
esac

if [[ ! -s "$selected_pairs_tsv" ]]; then
  if [[ "$STATS_MODE" != "1" ]]; then
    printf '~~~~ [API] failed calls: 0 ~~~~\n'
    printf '~~~~ NO NEW RECORDS FOUND ~~~~\n'
  fi
  exit 0
fi

if [[ "$STATS_MODE" == "1" ]]; then
  awk -F '\t' '
  {
    key = $3 SUBSEP $2
    total[key]++
    if ($4 == "obsolete") obsolete[key]++
    else active[key]++

    cve=$1
    all_cve[cve]=1
    if ($4 == "obsolete") obsolete_cve[cve]=1
    else active_cve[cve]=1
  }
  END {
    for (k in all_cve) total_unique++
    for (k in active_cve) active_unique++
    for (k in obsolete_cve) obsolete_unique++

    printf "[ UNIQUE CVE ]  ACTIVE: %d  |  OBSOLETE: %d  |  TOTAL: %d\n\n", active_unique+0, obsolete_unique+0, total_unique+0
    printf "%-10s  %-10s  %-10s  %-24s  %s\n", "TOTAL", "ACTIVE", "OBSOLETE", "SOURCE", "BINARY PACKAGE"

    for (k in total) {
      split(k, a, SUBSEP)
      pkg = a[1]
      src = a[2]
      printf "%10d  %10d  %10d  %-24s  %s\n", total[k], active[k]+0, obsolete[k]+0, src, pkg
    }
  }
  ' "$selected_pairs_tsv" > "$result_tsv"

  {
    sed -n '1,3p' "$result_tsv"
    tail -n +4 "$result_tsv" | sort -nr
  } > "$OUTPUT_FILE"

  cat "$OUTPUT_FILE"
  exit 0
fi

cut -f1 "$selected_pairs_tsv" | sort -u > "$unique_cves"
xargs -r -n1 -P "$JOBS" bash -lc 'fetch_one "$0"' < "$unique_cves" > "$scores_tsv"

awk -F '\t' -v min_score="$MIN_SCORE" '
NR==FNR { score[$1]=$2; next }
{
  s = (($1 in score) ? score[$1] : "N/A")
  if (s == "N/A") next
  if ((s + 0) <= (min_score + 0)) next

  status = ($4 == "obsolete") ? "[obsolete]" : "[active]"
  printf "%s\t%s\t%s\t%s\t%s\n", $1, s, $2, $3, status
}
' "$scores_tsv" "$selected_pairs_tsv" \
| LC_ALL=C sort -t $'\t' -k2,2gr -k1,1 -k3,3 -k4,4 > "$result_tsv"

awk -F '\t' '
BEGIN {
  printf "%-18s  %-5s  %-16s  %-36s  %s\n", "CVE", "Score", "Source", "Binary Package", "Status"
}
{
  printf "%-18s  %-5s  %-16s  %-36s  %s\n", $1, $2, $3, $4, $5
}
' "$result_tsv" > "$OUTPUT_FILE"

cat "$OUTPUT_FILE"
failed_count=$(awk -F '\t' '$3=="1"{n++} END{print n+0}' "$scores_tsv")
printf '~~~~ [API] failed calls: %s ~~~~\n' "$failed_count"
if [[ ! -s "$result_tsv" ]]; then
  printf '~~~~ NO NEW RECORDS FOUND ~~~~\n'
fi
