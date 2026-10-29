#!/bin/sh
# Runs every <incident>/test.sh. Used by `make test`.
set -u
cd "$(dirname "$0")/.." || exit 2
failed=0
total=0
for t in */test.sh */test-*.sh; do
  [ -f "$t" ] || continue
  total=$((total + 1))
  echo "== ${t%/test.sh}"
  if ! sh "$t"; then
    failed=$((failed + 1))
  fi
done
echo
echo "$total check folder(s) tested, $failed failed"
[ "$failed" -eq 0 ]
