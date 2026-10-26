#!/bin/sh
# Tests for check.sh. Run from anywhere: sh test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
fx="$here/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export BC_TMPDIRS="$fx/tmp-clean"

# 1. A path that does not exist: skipped, clean result.
run_check "missing path" sh "$here/check.sh" "$work/nope"
expect_code 0
expect_out "not a file, skipped"

# 2. Unknown option is a usage error.
run_check "bad option" sh "$here/check.sh" --bogus
expect_code 2

# 3. MD5 match. We add the MD5 of a plain file to the bad list.
printf 'not a real binary\n' > "$work/ovhcloud"
sum=$( (md5sum "$work/ovhcloud" 2>/dev/null || md5 -r "$work/ovhcloud") | cut -d' ' -f1)
run_check "md5 match" env BC_EXTRA_BAD_MD5="$sum" sh "$here/check.sh" "$work/ovhcloud"
expect_code 1
expect_out "matches a known bad build"

# 4. Same file without the extra hash: not on the list.
run_check "md5 no match" sh "$here/check.sh" "$work/ovhcloud"
expect_code 0
expect_out "not on the advisory's bad list"

# 5. Exposure window: put "now" inside a fake window.
now=$(date +%s)
run_check "ctime in window" env BC_WINDOW_START=$((now - 3600)) BC_WINDOW_END=$((now + 3600)) sh "$here/check.sh" "$work/ovhcloud"
expect_code 1
expect_out "inside the exposure window"

# 6. Staging folder with ten digits is flagged; decoys are not.
run_check "staging folder" env BC_TMPDIRS="$fx/tmp-with-stage" sh "$here/check.sh" "$work/nope"
expect_code 1
expect_out "envchecker-1792414999 exists"
run_check "decoy folders" env BC_TMPDIRS="$fx/tmp-decoy" sh "$here/check.sh" "$work/nope"
expect_code 0
expect_no_out "FLAG"

# 7. Real Go binaries, if Go is installed. Built here, never executed.
if command -v go >/dev/null 2>&1; then
  (cd "$fx/swapped-lookalike" && GOFLAGS='' CGO_ENABLED=0 go build -ldflags="-s -w" -o "$work/swapped/ovhcloud" main.go) || exit 1
  (cd "$fx/clean-build" && GOFLAGS='' CGO_ENABLED=0 go build -o "$work/clean/ovhcloud" main.go) || exit 1

  run_check "lookalike build" sh "$here/check.sh" "$work/swapped/ovhcloud"
  expect_code 1
  expect_out "contains commit 5ead8ef9b43d"
  expect_out 'built with -ldflags="-s -w"'

  run_check "clean build" sh "$here/check.sh" "$work/clean/ovhcloud"
  expect_code 0
  expect_no_out "FLAG"

  # Without Go on PATH the byte search still catches the commit id.
  mkdir -p "$work/nogo"
  for tool in sh md5sum md5 cut stat date grep sort sed awk rm mktemp; do
    p=$(command -v "$tool" 2>/dev/null) && ln -s "$p" "$work/nogo/$tool"
  done
  run_check "lookalike without go" env PATH="$work/nogo" sh "$here/check.sh" "$work/swapped/ovhcloud"
  expect_code 1
  expect_out "contains commit 5ead8ef9b43d"
  expect_out "Go is not installed"
else
  echo "  skip Go is not installed, binary fixture tests skipped"
fi

finish
