#!/bin/sh
# breach-checks: YYYY-MM-short-name
#
# One or two lines on what this looks for. Say plainly that it only reads files.
#
# Usage: sh check.sh [path ...]
#
# Exit codes: 0 nothing found, 1 something to look at, 2 usage error.
#
# Test hooks (used by test.sh, you do not need them):
#   BC_TMPDIRS   space separated folders to search instead of /tmp

set -u

case "${1:-}" in
  -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  -*) echo "unknown option: $1" >&2; exit 2 ;;
esac

# Indicators. Put the source of every value in a comment above it.
# Example: from the IOC table of <vendor advisory URL>.
IOC_SHA256="0000000000000000000000000000000000000000000000000000000000000000"

findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

echo "== first thing we check"
dirs="${BC_TMPDIRS:-/tmp}"
for d in $dirs; do
  [ -e "$d/example-marker" ] && flag "$d/example-marker exists"
done
[ "$findings" -eq 0 ] && note "none found"
: "$IOC_SHA256"

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Read 'If it flags something' in the README."
  exit 1
fi
echo "RESULT: nothing found."
exit 0
