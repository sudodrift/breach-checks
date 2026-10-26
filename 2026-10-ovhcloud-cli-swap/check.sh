#!/bin/sh
# breach-checks: 2026-10-ovhcloud-cli-swap
#
# Looks for the October 19, 2026 OVHcloud CLI release swap (GHSA-862f-55f5-vmvw)
# WITHOUT running the ovhcloud binary. It only reads files.
#
# Usage: sh check.sh [path-to-ovhcloud ...]
#   With no arguments it looks in PATH and the usual install folders.
#
# Exit codes: 0 nothing found, 1 something to look at, 2 usage error.
#
# Test hooks (used by test.sh, you do not need them):
#   BC_TMPDIRS          space separated folders to search for envchecker-* (default: /tmp and $TMPDIR)
#   BC_EXTRA_BAD_MD5    extra MD5 values to treat as bad
#   BC_WINDOW_START/END epoch seconds of the exposure window

set -u

# MD5 of the swapped binaries, from the appendix of GHSA-862f-55f5-vmvw.
BAD_MD5="6f2f086239f3d88eb2750e871901927d
347e65eb7f2d78d1c6872690272a6cc3
01f57206d37c28cf711677f612052913
301bff0b51980b9e76c93633e7cfd3bd
6a3cf153338c416169cda2fe704c8848"
if [ -n "${BC_EXTRA_BAD_MD5:-}" ]; then
  BAD_MD5="$BAD_MD5
$BC_EXTRA_BAD_MD5"
fi

# The commit the swapped build came from (vcs.revision in the advisory).
BAD_COMMIT="5ead8ef9b43d"

# 2026-10-19 12:47 UTC to 14:21 UTC (14:47 to 16:21 UTC+2 in the advisory).
WINDOW_START="${BC_WINDOW_START:-1792414020}"
WINDOW_END="${BC_WINDOW_END:-1792419660}"

case "${1:-}" in
  -h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  -*)
    echo "unknown option: $1" >&2
    exit 2 ;;
esac

findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

md5_of() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | cut -d' ' -f1
  elif command -v md5 >/dev/null 2>&1; then
    md5 -q "$1"
  else
    echo ""
  fi
}

ctime_of() {
  # Linux (GNU stat) first, then macOS/BSD stat.
  stat -c %Z "$1" 2>/dev/null || stat -f %c "$1" 2>/dev/null || echo ""
}

human_time() {
  date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null ||
    date -u -r "$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "$1"
}

if [ "$#" -gt 0 ]; then
  candidates=$(printf '%s\n' "$@")
else
  candidates=$(
    command -v ovhcloud 2>/dev/null
    for d in "$HOME/.local/bin" /usr/local/bin /usr/bin /opt/homebrew/bin "$HOME/go/bin" "$HOME/bin"; do
      [ -f "$d/ovhcloud" ] && echo "$d/ovhcloud"
    done
  )
fi

checked=0
# Read one path per line so folders with spaces work.
printf '%s\n' "$candidates" | sort -u > "${TMPDIR:-/tmp}/bc-ovh.$$"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  if [ ! -f "$p" ]; then
    echo "== $p"
    note "not a file, skipped"
    continue
  fi
  checked=$((checked + 1))
  echo "== $p"

  sum=$(md5_of "$p")
  if [ -z "$sum" ]; then
    note "no md5sum or md5 tool found, MD5 check skipped"
  elif printf '%s\n' "$BAD_MD5" | grep -qx "$sum"; then
    flag "md5 $sum matches a known bad build from the advisory"
  else
    note "md5 $sum is not on the advisory's bad list"
  fi

  ct=$(ctime_of "$p")
  if [ -n "$ct" ]; then
    if [ "$ct" -ge "$WINDOW_START" ] && [ "$ct" -le "$WINDOW_END" ]; then
      flag "file landed on disk (ctime $(human_time "$ct")) inside the exposure window"
    else
      note "ctime $(human_time "$ct"), outside the exposure window"
    fi
  fi

  # Byte search, no execution. The swapped build embeds its commit id.
  if grep -a -q "$BAD_COMMIT" "$p" 2>/dev/null; then
    flag "binary contains commit $BAD_COMMIT (the commit the swapped build came from)"
  fi

  # go version -m reads the embedded build info from the file. It does not run it.
  if command -v go >/dev/null 2>&1; then
    info=$(go version -m "$p" 2>/dev/null)
    if [ -n "$info" ]; then
      printf '%s\n' "$info" | awk '$1=="mod"{print "   module: "$2" "$3}'
      if printf '%s\n' "$info" | grep -q 'ldflags="-s -w"'; then
        flag 'built with -ldflags="-s -w", the same build flags the advisory shows for the swapped binary'
      fi
    else
      note "go version -m found no Go build info"
    fi
  else
    note "Go is not installed, build info check skipped (the commit byte search above still ran)"
  fi
done < "${TMPDIR:-/tmp}/bc-ovh.$$"
rm -f "${TMPDIR:-/tmp}/bc-ovh.$$"

if [ "$checked" -eq 0 ]; then
  echo "== no ovhcloud binary found (pass a path if it lives somewhere else)"
fi

echo "== staging folders (envchecker-*)"
dirs="${BC_TMPDIRS:-/tmp ${TMPDIR:-}}"
found_stage=0
for d in $dirs; do
  [ -d "$d" ] || continue
  for s in "$d"/envchecker-*; do
    [ -e "$s" ] || continue
    name=${s##*/}
    digits=${name#envchecker-}
    case "$digits" in
      *[!0-9]*|"") continue ;;
    esac
    n=${#digits}
    if [ "$n" -eq 9 ] || [ "$n" -eq 10 ]; then
      flag "staging folder $s exists (the stealer never deletes it)"
      found_stage=1
    fi
  done
done
[ "$found_stage" -eq 0 ] && note "none found (a reboot or tmp cleaner may have removed them, so this alone proves nothing)"

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Read the README section 'If it flags something'."
  exit 1
fi
echo "RESULT: nothing found."
exit 0
