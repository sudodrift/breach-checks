#!/bin/sh
# Tests for check.sh. Run from anywhere: sh test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
fx="$here/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Materialize fixtures with real names.
mkdir -p "$work/logs-hit" "$work/logs-clean" "$work/web-hit/html" "$work/web-clean/html"
cp "$fx/logs-hit/php-error.log.fixture" "$work/logs-hit/php-error.log"
cp "$fx/logs-hit/apache-error.log.fixture" "$work/logs-hit/apache-error.log"
cp "$fx/logs-clean/php-error.log.fixture" "$work/logs-clean/php-error.log"
cp "$fx/web-hit/html/shell.php.fixture" "$work/web-hit/html/shell.php"
cp "$fx/web-clean/html/index.php.fixture" "$work/web-clean/html/index.php"
# Make shell.php look recently modified relative to a fixed "now".
now=1793000000
touch -d "@$now" "$work/web-hit/html/shell.php" 2>/dev/null || touch -t 202610211200 "$work/web-hit/html/shell.php"
# Clean file is old.
touch -d "@$((now - 30*86400))" "$work/web-clean/html/index.php" 2>/dev/null || true

run_check "bad option" sh "$here/check.sh" --nope
expect_code 2

run_check "unfixed version" \
  env BC_PHP_BIN="$fx/phpbins/php-unfixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" sh "$here/check.sh"
expect_code 1
expect_out "FLAG: PHP 8.4.20 is below the fixed release"

run_check "fixed version clean" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" BC_NOW_EPOCH="$now" BC_RECENT_DAYS=7 \
      sh "$here/check.sh"
expect_code 0
expect_out "meets or exceeds the fixed release"
expect_no_out "FLAG"

run_check "eol version" \
  env BC_PHP_BIN="$fx/phpbins/php-eol" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" sh "$here/check.sh"
expect_code 1
expect_out "FLAG: PHP 8.1.32 is below the fixed release"

run_check "log signals" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-hit" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" sh "$here/check.sh"
expect_code 1
expect_out "memory exhaustion in Unknown on line 0"
expect_out "AH00052 segmentation fault"

run_check "shell spawn" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/shell-spawn.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" sh "$here/check.sh"
expect_code 1
expect_out "web/php user may be running a shell"

run_check "audit shell" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/hit.fixture" \
      BC_WEB_ROOTS="$work/web-clean" sh "$here/check.sh"
expect_code 1
expect_out "audit log shows a shell"

run_check "recent php in web root" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-hit" BC_NOW_EPOCH="$now" BC_RECENT_DAYS=7 \
      sh "$here/check.sh"
expect_code 1
expect_out "PHP file modified within 7d"

# Near miss: clean logs must not match "Unknown on line 0" style.
run_check "near miss clean notice" \
  env BC_PHP_BIN="$fx/phpbins/php-fixed" BC_LOG_DIRS="$work/logs-clean" \
      BC_PROC_LIST="$fx/proc/clean.fixture" BC_AUDIT_LOG="$fx/audit/clean.fixture" \
      BC_WEB_ROOTS="$work/web-clean" BC_NOW_EPOCH="$now" BC_RECENT_DAYS=7 \
      sh "$here/check.sh"
expect_code 0
expect_no_out "FLAG"

finish
