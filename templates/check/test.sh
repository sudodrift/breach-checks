#!/bin/sh
# Tests for check.sh. Run from anywhere: sh test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
fx="$here/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Build fixture trees in $work from files in $fx (they end in .fixture).
mkdir -p "$work/tmp-hit" "$work/tmp-clean"
: > "$work/tmp-hit/example-marker"
: "$fx"

run_check "bad option" sh "$here/check.sh" --nope
expect_code 2

run_check "marker present" env BC_TMPDIRS="$work/tmp-hit" sh "$here/check.sh"
expect_code 1
expect_out "example-marker exists"

run_check "clean" env BC_TMPDIRS="$work/tmp-clean" sh "$here/check.sh"
expect_code 0
expect_no_out "FLAG"

finish
