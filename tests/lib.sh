# Small helpers for the per-check test.sh files. Sourced, not run.
# shellcheck shell=sh

T_PASS=0
T_FAIL=0
T_OUT=""
T_CODE=0

# run_check <description> <command...>: runs a command and keeps output and exit code.
run_check() {
  T_DESC=$1
  shift
  T_OUT=$("$@" 2>&1)
  T_CODE=$?
}

ok() { T_PASS=$((T_PASS + 1)); echo "  ok   $T_DESC: $1"; }
bad() {
  T_FAIL=$((T_FAIL + 1))
  echo "  FAIL $T_DESC: $1"
  printf '%s\n' "$T_OUT" | sed 's/^/       | /'
}

expect_code() {
  if [ "$T_CODE" -eq "$1" ]; then ok "exit code $1"; else bad "exit code $T_CODE, wanted $1"; fi
}

expect_out() {
  if printf '%s\n' "$T_OUT" | grep -q -- "$1"; then ok "output has '$1'"; else bad "output lacks '$1'"; fi
}

expect_no_out() {
  if printf '%s\n' "$T_OUT" | grep -q -- "$1"; then bad "output has '$1' but should not"; else ok "output lacks '$1'"; fi
}

finish() {
  echo "  $T_PASS passed, $T_FAIL failed"
  [ "$T_FAIL" -eq 0 ]
}
