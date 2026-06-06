# debian-security-tracker
It maps CVEs to Debian packages and shows fix status by Debian release.

  ## What It Is

  Debian Security Tracker is Debian’s central list of known security issues.

  It maps CVEs to Debian packages and shows fix status by Debian release.

  ## Why It Is Used

  It gives a trusted source for vulnerability status in Debian.

  It helps teams decide what to patch first.

  ## How It Is Used

  1. Run `debsecan` on a host.
  2. `debsecan` checks installed packages against binary packages at `/var/lib/dpkg/status`.
  3. Use the returned CVEs with `curl` to fetch CVSS scores.
  4. Use results to find active risk, available fixes, and patch priority.

  ## Source

  - [7.3. Security Tracker](https://www.debian.org/doc/manuals/securing-debian-manual/ch07s03.en.html)
  - [Debian Security Team](https://security-team.debian.org/security_tracker.html)

  ## Definitions

  `Obsolete` = package is not from your current active Debian repo set anymore.

  `Active` = still in current repos.

  Check the status with:

  ```bash
  apt policy <package>
  ```

  Then check the version table.

  ## Debsecan Feed Behavior

  `debsecan` makes one HTTP GET request, similar to `curl`, to download the suite feed.

  It then decompresses the feed and parses all vulnerability records in memory.

  We can trace network syscalls with:

  ```bash
  strace -f -e trace=connect,sendto,recvfrom -s 256 debsecan --suite bookworm --only-fixed --format detail 2>&1 >/dev/null | less
  ```

  We can manually fetch and parse the suite feed:

  ```bash
  curl -fsSL 'https://security-tracker.debian.org/tracker/debsecan/release/1/bookworm' | python3 -c 'import sys,zlib;
  sys.stdout.write(zlib.decompress(sys.stdin.buffer.read()).decode("utf-8","replace"))' | less
  ```

  ```bash
  time curl -fsSL 'https://security-tracker.debian.org/tracker/debsecan/release/1/bookworm' | python3 -c 'import sys,zlib;
  sys.stdout.write(zlib.decompress(sys.stdin.buffer.read()).decode("utf-8","replace"))' | wc -l
  ```

  ## Basic Debsecan Checks

  ```bash
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format packages
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail
  ```

  ## CVE Totals

  ```bash
  # Total unique CVEs
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail | grep -i cve | sort -u | wc -l

  # Total unique obsolete CVEs
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail | awk 'BEGIN{RS=""} /package is obsolete/' | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u | wc -l

  # Total unique active CVEs
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail | awk 'BEGIN{RS=""} $0 !~ /package is obsolete/' | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u | wc -l
  ```

  ## Check Failed Calls

  ```bash
  debsecan --suite "$(lsb_release -sc)" --only-fixed --format detail | awk 'BEGIN{RS="";FS="\n"} match($0,/^CVE-[0-9]{4}-[0-9]+/){print substr($0,RSTART,RLENGTH)}' | sort -u | while read -r cve; do code="$(curl -sS -L --max-time 20 -o /dev/null -w "%{http_code}" "https://cveawg.mitre.org/api/cve/$cve")"; [ "$code" = "200" ] || echo "$cve API_FAIL $code"; done
  ```

  ## CVE API Rate-Limit Check

  MITRE API docs: Swagger UI

  ```bash
  curl -sS -D - -o /dev/null https://cveawg.mitre.org/api/cve/CVE-2024-3094 | grep -i '^ratelimit-\|^retry-after\|^http/'
  ```

  `RateLimit-Remaining` explains how many quota units are left in the current expiring window.

  Treat it as a health check of how many more requests the API can currently accept.

  When `RateLimit-Remaining` gets low, throttling may occur soon, so reduce your request rate.

  ## Cron Example For Report Mail

  ```cron
  # debsecan - security updates
  30 * * * * root /bin/bash -lc 'out=$(/root/ersad_temp/debsecan_cve_scores.sh --cve-score 7.5 --jobs 8 --only-active 2>&1); printf "\%s\n" "$out" | grep -qx "~~~~ NO NEW RECORDS FOUND ~~~~"
  || printf "\%s\n" "$out" | /usr/bin/mail -s "debsecan CVE report $(date +\%F)" server-admins@motrada.net'

  # DSA Alerts
  */30 * * * * root /bin/bash -lc 'out=$(/usr/local/bin/dsa_new_cve_scores.sh 2>&1); printf "\%s\n" "$out" | grep -qx "~~~~ NO NEW RECORDS FOUND ~~~~" || printf "\%s\n" "$out" | /usr/bin/
  mail -s "DSA CVE report $(date +\%F\ \%R)" server-admins@motrada.net'
  ```

  ## Script Usage: `debsecan_cve_scores.sh`

  Collects CVEs from `debsecan --only-fixed`.

  Fetches CVSS scores from the CVE API.

  Filters by score threshold.

  Outputs sorted results.

  ```bash
  ./debsecan_cve_scores.sh -h
  ```

  ```text
  Usage: debsecan_cve_scores.sh [OPTIONS]

  Collect CVEs from debsecan (--only-fixed), enrich with CVSS score from CVE API,
  filter by score threshold, and print/write sorted results.

  Options:
    -h, --help                             Show this help and exit
    --cve-score VALUE, --cve-score=VALUE   CVSS threshold (print score > VALUE; default: 8)
    --jobs N                               Parallel CVE API requests (default: 2)
    --all                                  Include active and obsolete (default)
    --only-active                          Include only active entries
    --only-obsolete                        Include only obsolete entries

  Stats Mode:
    --stats                                Print per package/source stats (TOTAL/ACTIVE/OBSOLETE)
                                           Can be combined with: --all / --only-active / --only-obsolete
                                           Cannot be combined with: --cve-score, --jobs

  Output:
    Printed to stdout and written to:
      /run/active_cve_scores/debsecan_cve_scores.tsv
    (overwritten on each run)
  ```

  ### Examples

  ```bash
  ./debsecan_cve_scores.sh --stats
  ./debsecan_cve_scores.sh --search-package php
  ./debsecan_cve_scores.sh --search-package syslog --cve-score 7
  ./debsecan_cve_scores.sh --all
  ./debsecan_cve_scores.sh --all --jobs 8 --cve-score 7
  ./debsecan_cve_scores.sh --only-active
  ./debsecan_cve_scores.sh --only-active --jobs 8 --cve-score 7
  ./debsecan_cve_scores.sh --only-obsolete
  ./debsecan_cve_scores.sh --only-obsolete --jobs 8 --cve-score 7
  ```

  ## Script Usage: `dsa_new_cve_scores.sh`

  Track and search for new Debian Security Advisories and print CVE scores.

  ```bash
  ./dsa_new_cve_scores.sh -h
  ```

  ```text
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
  ```

  ### Examples
  ```bash
  ./dsa_new_cve_scores.sh
  ./dsa_new_cve_scores.sh --jobs 5
  ./dsa_new_cve_scores.sh --search-dsa DSA-6256-1 DSA-6253-1
  ./dsa_new_cve_scores.sh --search-dsa DSA-6256-1 dsa-6253-1 --jobs 5
  ```
