#!/bin/sh
# breach-checks: 2026-10-php2shell
#
# Looks for signs that this Linux box is still running an unfixed PHP build
# for CVE-2026-109618 / CVE-2026-109619 ("php2shell"), or that a web PHP
# worker may already have been abused. Read only. Never starts PHP for a
# web request and never runs a PoC.
#
# Usage: sh check.sh
#
# Exit codes: 0 nothing found, 1 something to look at, 2 usage error.
#
# Test hooks (used by test.sh, you do not need them):
#   BC_PHP_BIN          path to a fake "php" binary (executable script)
#   BC_PHP_VERSION      force the version string if BC_PHP_BIN is unset
#   BC_PHP_SAPI         force the SAPI string (cli, fpm-fcgi, apache2handler, ...)
#   BC_LOG_DIRS         space separated folders of log files to scan
#   BC_PROC_LIST        file whose contents stand in for `ps -eo user,pid,ppid,args`
#   BC_AUDIT_LOG        file to grep instead of ausearch/journalctl
#   BC_WEB_ROOTS        space separated web roots to scan for recent .php files
#   BC_RECENT_DAYS      modified-within window for web-root PHP files (default 7)
#   BC_NOW_EPOCH        fixed "now" for recent-file checks (tests)

set -u

case "${1:-}" in
  -h|--help)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  -*)
    echo "unknown option: $1" >&2
    exit 2 ;;
esac

# Fixed upstream releases for both CVEs, from CISA alert 2026-10-21 and the
# PHP security advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp.
# https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
FIXED_85="8.5.12"
FIXED_84="8.4.27"
FIXED_83="8.3.36"
FIXED_82="8.2.35"

findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

# Compare dotted versions: returns 0 if $1 < $2, 1 if $1 >= $2.
ver_lt() {
  # shellcheck disable=SC2086
  set -- $(echo "$1" | tr '.' ' ') $(echo "$2" | tr '.' ' ')
  a1=${1:-0}; a2=${2:-0}; a3=${3:-0}
  b1=${4:-0}; b2=${5:-0}; b3=${6:-0}
  [ "$a1" -lt "$b1" ] && return 0
  [ "$a1" -gt "$b1" ] && return 1
  [ "$a2" -lt "$b2" ] && return 0
  [ "$a2" -gt "$b2" ] && return 1
  [ "$a3" -lt "$b3" ] && return 0
  return 1
}

is_fixed() {
  v=$1
  case "$v" in
    8.5.*) ver_lt "$v" "$FIXED_85" && return 1; return 0 ;;
    8.4.*) ver_lt "$v" "$FIXED_84" && return 1; return 0 ;;
    8.3.*) ver_lt "$v" "$FIXED_83" && return 1; return 0 ;;
    8.2.*) ver_lt "$v" "$FIXED_82" && return 1; return 0 ;;
    8.1.*|8.0.*|7.*|5.*) return 1 ;; # EOL upstream; treat as not fixed
    *) return 1 ;;
  esac
}

parse_version() {
  # Pull X.Y.Z from "PHP X.Y.Z ..." or bare X.Y.Z
  echo "$1" | sed -n 's/.*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1
}

echo "== PHP version and SAPI"
php_bin="${BC_PHP_BIN:-}"
if [ -z "$php_bin" ] && command -v php >/dev/null 2>&1; then
  php_bin=$(command -v php)
fi

versions_seen=0
if [ -n "${BC_PHP_VERSION:-}" ]; then
  versions_seen=1
  ver=$(parse_version "$BC_PHP_VERSION")
  sapi=${BC_PHP_SAPI:-unknown}
  echo "== php (forced)"
  note "version $ver  SAPI $sapi"
  if [ -z "$ver" ]; then
    note "could not parse version from BC_PHP_VERSION"
  elif is_fixed "$ver"; then
    note "meets or exceeds the fixed release for its branch"
  else
    flag "PHP $ver is below the fixed release for its branch (need 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor backport)"
  fi
  case "$sapi" in
    *apache*|*fpm*|*cgi*|*litespeed*|*franken*)
      note "SAPI $sapi serves web requests; CISA lists these as in scope" ;;
    cli|cli-server)
      note "SAPI $sapi is not a typical web SAPI; still check any FPM/mod_php package on the box" ;;
  esac
elif [ -n "$php_bin" ] && [ -x "$php_bin" ]; then
  versions_seen=1
  out=$("$php_bin" -v 2>/dev/null | head -1)
  sapi=$("$php_bin" -r 'echo PHP_SAPI;' 2>/dev/null || echo unknown)
  ver=$(parse_version "$out")
  echo "== $php_bin"
  note "php -v: $out"
  note "SAPI: $sapi"
  if [ -z "$ver" ]; then
    note "could not parse a version from php -v"
  elif is_fixed "$ver"; then
    note "meets or exceeds the fixed release for its branch"
  else
    flag "PHP $ver is below the fixed release for its branch (need 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor backport)"
  fi
else
  note "no php binary in PATH (set BC_PHP_BIN or install php-cli to inventory the CLI build)"
fi

# Also look for packaged php-fpm binaries without relying on PATH.
for cand in /usr/sbin/php-fpm /usr/sbin/php-fpm8.2 /usr/sbin/php-fpm8.3 /usr/sbin/php-fpm8.4 /usr/sbin/php-fpm8.5 \
            /usr/bin/php8.2 /usr/bin/php8.3 /usr/bin/php8.4 /usr/bin/php8.5; do
  [ -x "$cand" ] || continue
  [ "$cand" = "${php_bin:-}" ] && continue
  versions_seen=1
  out=$("$cand" -v 2>/dev/null | head -1)
  ver=$(parse_version "$out")
  echo "== $cand"
  note "php -v: $out"
  if [ -n "$ver" ] && ! is_fixed "$ver"; then
    flag "PHP $ver at $cand is below the fixed release for its branch"
  elif [ -n "$ver" ]; then
    note "meets or exceeds the fixed release for its branch"
  fi
done

if [ "$versions_seen" -eq 0 ]; then
  note "no PHP binary found on this host"
fi

echo "== crash and memory-exhaustion lines in logs"
# Indicators from Datadog Security Labs reproduction and CISA monitoring advice.
# https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
log_dirs="${BC_LOG_DIRS:-/var/log/apache2 /var/log/httpd /var/log/nginx /var/log/php /var/log/php-fpm /var/log}"
log_hits=0
for d in $log_dirs; do
  [ -d "$d" ] || continue
  # Restrict to common log names to stay read-only and cheap.
  for f in "$d"/*error* "$d"/*php* "$d"/syslog "$d"/messages; do
    [ -f "$f" ] || continue
    [ -r "$f" ] || continue
    # Memory exhaustion before any script: "in Unknown on line 0"
    if grep -a -q 'Allowed memory size .* exhausted .* in Unknown on line 0' "$f" 2>/dev/null; then
      flag "$f contains PHP memory exhaustion in Unknown on line 0 (Datadog php2shell signal)"
      log_hits=$((log_hits + 1))
    fi
    # Apache worker segfault
    if grep -a -q 'AH00052:.*Segmentation fault' "$f" 2>/dev/null; then
      flag "$f contains AH00052 segmentation fault (Apache worker crash)"
      log_hits=$((log_hits + 1))
    fi
    # Generic PHP segfault / child exit
    if grep -a -qiE 'php.*(segfault|segmentation fault)|exit signal Segmentation fault' "$f" 2>/dev/null; then
      # Avoid double-counting AH00052 already flagged
      if ! grep -a -q 'AH00052:.*Segmentation fault' "$f" 2>/dev/null; then
        flag "$f contains a PHP or child segmentation fault line"
        log_hits=$((log_hits + 1))
      fi
    fi
  done
done
[ "$log_hits" -eq 0 ] && note "no matching crash or OOM-before-script lines in readable logs"

echo "== web users spawning shells"
# CISA: monitor PHP worker processes launching shells.
# Datadog: apache2/php-fpm spawning sh/bash is the most direct evidence.
proc_src="${BC_PROC_LIST:-}"
if [ -n "$proc_src" ] && [ -f "$proc_src" ]; then
  proc=$(cat "$proc_src")
else
  proc=$(ps -eo user,pid,ppid,args 2>/dev/null || ps aux 2>/dev/null || echo "")
fi
shell_hits=0
if [ -n "$proc" ]; then
  # Look for www-data/apache/nginx/php-fpm users running a shell or downloader.
  printf '%s\n' "$proc" | awk '
    BEGIN { IGNORECASE=1 }
    $1 ~ /^(www-data|apache|nginx|httpd|php|php-fpm)/ {
      line=$0
      # skip the php/apache binary itself
      if ($0 ~ /(bash|\/sh |\/sh$| dash |\/dash |zsh|curl |wget |nc |ncat |python3? -c|perl -e)/) {
        print
      }
    }
  ' > "${TMPDIR:-/tmp}/bc-php2shell-proc.$$"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    flag "process list: web/php user may be running a shell or downloader: $line"
    shell_hits=$((shell_hits + 1))
  done < "${TMPDIR:-/tmp}/bc-php2shell-proc.$$"
  rm -f "${TMPDIR:-/tmp}/bc-php2shell-proc.$$"
fi
[ "$shell_hits" -eq 0 ] && note "no web/php user shell or downloader processes seen in the process list"

# auditd / journal hints when present
audit_src="${BC_AUDIT_LOG:-}"
audit_hits=0
if [ -n "$audit_src" ] && [ -f "$audit_src" ]; then
  if grep -Eiq 'exe="(/bin/|/usr/bin/)(ba)?sh".*uid=(33|48|99|nginx|www-data)|comm="(ba)?sh".*(www-data|apache|nginx|php-fpm)' "$audit_src" 2>/dev/null; then
    flag "audit log shows a shell associated with a web/php identity"
    audit_hits=$((audit_hits + 1))
  fi
elif command -v ausearch >/dev/null 2>&1; then
  # Best-effort, may need root; ignore failures.
  if ausearch -m EXECVE -i 2>/dev/null | grep -Eiq 'exe=/bin/(ba)?sh.*uid=(www-data|apache|nginx)|comm=(ba)?sh.*(www-data|apache|nginx)' ; then
    flag "ausearch shows a shell associated with a web/php identity"
    audit_hits=$((audit_hits + 1))
  fi
elif command -v journalctl >/dev/null 2>&1; then
  if journalctl -q -n 500 --no-pager 2>/dev/null | grep -Eiq 'php.*(segfault|segmentation)|AH00052'; then
    flag "journalctl recent lines mention PHP/Apache segfaults"
    audit_hits=$((audit_hits + 1))
  fi
fi
[ "$audit_hits" -eq 0 ] && note "no extra audit/journal shell or segfault hits (or tools not available)"

echo "== recently modified PHP files in web roots"
days="${BC_RECENT_DAYS:-7}"
now="${BC_NOW_EPOCH:-}"
roots="${BC_WEB_ROOTS:-/var/www /usr/share/nginx/html /srv/www /var/www/html}"
recent_hits=0
for root in $roots; do
  [ -d "$root" ] || continue
  # Prefer find -mtime; fall back to listing when BC_NOW_EPOCH is set for tests.
  if [ -n "$now" ]; then
    # Test mode: flag .php files whose mtime is within days of BC_NOW_EPOCH
    cutoff=$((now - days * 86400))
    find "$root" -type f -name '*.php' 2>/dev/null | while IFS= read -r f; do
      mt=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)
      if [ "$mt" -ge "$cutoff" ]; then
        echo "$f"
      fi
    done > "${TMPDIR:-/tmp}/bc-php2shell-recent.$$"
  else
    find "$root" -type f -name '*.php' -mtime -"$days" 2>/dev/null > "${TMPDIR:-/tmp}/bc-php2shell-recent.$$"
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    flag "PHP file modified within ${days}d: $f"
    recent_hits=$((recent_hits + 1))
  done < "${TMPDIR:-/tmp}/bc-php2shell-recent.$$"
  rm -f "${TMPDIR:-/tmp}/bc-php2shell-recent.$$"
done
[ "$recent_hits" -eq 0 ] && note "no .php files modified in the last ${days} days under the usual web roots"

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Read 'If it flags something' in the README."
  exit 1
fi
echo "RESULT: nothing found."
exit 0
