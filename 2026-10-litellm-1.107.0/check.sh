#!/bin/sh
# breach-checks: 2026-10-litellm-1.107.0
#
# Looks for the malicious litellm 1.107.0 release (October 21, 2026) WITHOUT
# starting Python. Starting any Python in an affected environment, pip included,
# runs the payload again, so this script only uses find, grep, awk and a hash tool.
#
# Usage: sh check.sh [folder ...]
#   With no arguments it searches $HOME and the usual Python install folders.
#   Pass project folders to also scan their lockfiles.
#
# Exit codes: 0 nothing found, 1 something to look at, 2 usage error.
#
# Test hooks (used by test.sh, you do not need them):
#   BC_TMPDIRS   space separated folders to search for marker files (default: /tmp)
#   BC_NO_DOCKER set to 1 to skip the local Docker image check

set -u

case "${1:-}" in
  -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  -*) echo "unknown option: $1" >&2; exit 2 ;;
esac

BAD_VERSION="1.107.0"
# Earlier poisoned releases from March 2026, listed in the same OSV entry (MAL-2026-2144).
OLD_BAD_VERSIONS="1.82.7 1.82.8"

# SHA-256 of cook.pth, cook.py and sitecustomize.py, from the Microsoft Security
# Blog IOC table (LF and CRLF variants) and OSV MAL-2026-2144.
IOC_SHA256="7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb
84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d
9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25
03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea
34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa
b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465"

# Wheel SHA-256 values from the Microsoft Security Blog IOC table.
IOC_WHEEL_SHA256="7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d
0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a
668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6
462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7
c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054
1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00
12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484"

# Image index digests from the LiteLLM incident post (main, database, non_root).
IOC_DIGEST_PREFIXES="1bbcb1443bc9 c00f9d92c427 7b00e91cd2fe"

findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo ""
  fi
}

is_ioc() { [ -n "$2" ] && printf '%s\n' "$1" | grep -qx "$2"; }

if [ "$#" -gt 0 ]; then
  roots=$(printf '%s\n' "$@")
else
  roots=$(
    for d in "$HOME" /usr/lib /usr/local/lib /usr/lib64 /opt /Library/Frameworks/Python.framework /opt/homebrew/lib /usr/local/Cellar; do
      [ -d "$d" ] && echo "$d"
    done
  )
fi

list=$(mktemp "${TMPDIR:-/tmp}/bc-litellm.XXXXXX") || exit 2
trap 'rm -f "$list"' EXIT

# One pass of find over all roots. Skips virtual filesystems, git internals and
# node_modules. Collects every path we care about into $list.
printf '%s\n' "$roots" | while IFS= read -r r; do
  [ -d "$r" ] || continue
  find "$r" \( -path /proc -o -path /sys -o -path /dev -o -name .git -o -name node_modules \) -prune -o \
    \( -name 'litellm-*.dist-info' -o -name 'litellm-*.egg-info' \
       -o -name 'cook.pth' -o -name 'cook.py' -o -name 'sitecustomize.py' -o -name 'cook.*.pyc' \
       -o -name 'litellm-*.whl' -o -name 'litellm-*.json' \
       -o -name 'requirements*.txt' -o -name 'constraints*.txt' -o -name 'uv.lock' -o -name 'poetry.lock' \
       -o -name 'pdm.lock' -o -name 'Pipfile.lock' -o -name 'pylock*.toml' \) -print 2>/dev/null
done | sort -u > "$list"

echo "== installed litellm versions (dist-info, egg-info, conda-meta)"
seen=0
while IFS= read -r p; do
  base=${p##*/}
  case "$base" in
    litellm-*.dist-info|litellm-*.egg-info)
      ver=${base#litellm-}; ver=${ver%.dist-info}; ver=${ver%.egg-info}; ver=${ver%%-py*}
      ;;
    litellm-*.json)
      case "$p" in */conda-meta/*) ;; *) continue ;; esac
      ver=${base#litellm-}; ver=${ver%%-*}
      ;;
    *) continue ;;
  esac
  seen=$((seen + 1))
  if [ "$ver" = "$BAD_VERSION" ]; then
    flag "litellm $ver at $p"
  else
    bad_old=0
    for o in $OLD_BAD_VERSIONS; do [ "$ver" = "$o" ] && bad_old=1; done
    if [ "$bad_old" -eq 1 ]; then
      flag "litellm $ver at $p (one of the March 2026 poisoned releases)"
    else
      note "litellm $ver at $p"
    fi
  fi
done < "$list"
[ "$seen" -eq 0 ] && note "no installed litellm found"

echo "== startup hook files (cook.pth, cook.py, sitecustomize.py)"
seen=0
while IFS= read -r p; do
  base=${p##*/}
  case "$base" in
    cook.pth|cook.py|sitecustomize.py|cook.*.pyc) ;;
    *) continue ;;
  esac
  parent=${p%/*}
  pname=${parent##*/}
  sum=$(sha256_of "$p")
  seen=$((seen + 1))
  if is_ioc "$IOC_SHA256" "$sum"; then
    flag "$p sha256 matches a published IOC"
    continue
  fi
  case "$base" in
    sitecustomize.py)
      # Debian and Ubuntu ship one for the system Python. Only a hash match counts.
      note "$p (hash not on the IOC list, sitecustomize.py alone is normal)"
      ;;
    cook.*.pyc)
      gp=${parent%/*}
      gpname=${gp##*/}
      if [ "$pname" = "__pycache__" ] && { [ "$gpname" = site-packages ] || [ "$gpname" = dist-packages ]; }; then
        flag "$p compiled cook module next to the top of $gp"
      else
        note "$p (not under a site-packages folder, probably unrelated)"
      fi
      ;;
    *)
      case "$pname" in
        site-packages|dist-packages) flag "$p sits at the top of $parent (where the payload installs itself)" ;;
        *) note "$p (not at the top of a site-packages folder, probably unrelated)" ;;
      esac
      ;;
  esac
done < "$list"
[ "$seen" -eq 0 ] && note "none found"

echo "== cached wheels"
seen=0
while IFS= read -r p; do
  base=${p##*/}
  case "$base" in litellm-*.whl) ;; *) continue ;; esac
  seen=$((seen + 1))
  sum=$(sha256_of "$p")
  if is_ioc "$IOC_WHEEL_SHA256" "$sum"; then
    flag "$p sha256 matches a published malicious wheel"
  else
    case "$base" in
      "litellm-$BAD_VERSION-"*) flag "$p is a $BAD_VERSION wheel" ;;
      *) note "$p" ;;
    esac
  fi
done < "$list"
# uv and pip caches do not always keep the .whl name. Look for folder names too.
for c in "$HOME/.cache/uv" "$HOME/.cache/pip" "$HOME/Library/Caches/uv" "$HOME/Library/Caches/pip"; do
  [ -d "$c" ] || continue
  hits=$(find "$c" -ipath "*litellm*$BAD_VERSION*" -prune -print 2>/dev/null | head -n 5)
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | while IFS= read -r h; do echo "   FLAG: cache entry $h"; done
    findings=$((findings + 1))
    seen=$((seen + 1))
  fi
done
[ "$seen" -eq 0 ] && note "none found"

echo "== lockfiles and requirements pinning $BAD_VERSION"
seen=0
while IFS= read -r p; do
  base=${p##*/}
  case "$base" in
    requirements*.txt|constraints*.txt)
      if grep -n -i -E "^[[:space:]]*litellm(\[[^]]*\])?[[:space:]]*===?[[:space:]]*$(echo "$BAD_VERSION" | sed 's/\./\\./g')([[:space:];#]|$)" "$p" >/dev/null 2>&1; then
        flag "$p pins litellm==$BAD_VERSION"; seen=$((seen + 1))
      fi
      ;;
    uv.lock|poetry.lock|pdm.lock|pylock*.toml)
      # name = "litellm" followed by version = "1.107.0" in the same block.
      if awk -v v="$BAD_VERSION" '
          /^\[/ { inpkg = 0 }
          /^name[[:space:]]*=[[:space:]]*"litellm"/ { inpkg = 1; next }
          inpkg && $0 ~ "^version[[:space:]]*=[[:space:]]*\"" v "\"" { found = 1 }
          END { exit found ? 0 : 1 }' "$p"; then
        flag "$p locks litellm $BAD_VERSION"; seen=$((seen + 1))
      fi
      ;;
    Pipfile.lock)
      if awk -v v="$BAD_VERSION" '
          /"litellm"[[:space:]]*:/ { inpkg = 1 }
          inpkg && /"version"/ { if (index($0, "==" v "\"")) found = 1; inpkg = 0 }
          END { exit found ? 0 : 1 }' "$p"; then
        flag "$p locks litellm $BAD_VERSION"; seen=$((seen + 1))
      fi
      ;;
  esac
done < "$list"
[ "$seen" -eq 0 ] && note "none found"

echo "== marker and lock files"
dirs="${BC_TMPDIRS:-/tmp}"
seen=0
for d in $dirs; do
  [ -d "$d" ] || continue
  if [ -e "$d/.pc_once_72129118c59f5636c0bb" ]; then
    flag "$d/.pc_once_72129118c59f5636c0bb exists: the stealer reported a successful upload"; seen=1
  fi
  if [ -e "$d/remote_code_loader.lock" ]; then
    flag "$d/remote_code_loader.lock exists: the background loader ran here"; seen=1
    if command -v fuser >/dev/null 2>&1; then
      pids=$(fuser "$d/remote_code_loader.lock" 2>/dev/null)
      [ -n "$pids" ] && note "process(es) holding the lock right now:$pids"
    fi
  fi
  for s in "$d"/.pc_e_* "$d"/.pc_sq_*; do
    [ -e "$s" ] || continue
    flag "$s exists (temporary folder used by the stealer)"; seen=1
  done
done
[ "$seen" -eq 0 ] && note "none found (containers and tmp cleaners remove these, so this alone proves nothing)"

echo "== local Docker images"
if [ "${BC_NO_DOCKER:-0}" = "1" ]; then
  note "skipped"
elif command -v docker >/dev/null 2>&1 && imgs=$(docker images --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}}' 2>/dev/null); then
  seen=0
  for pfx in $IOC_DIGEST_PREFIXES; do
    m=$(printf '%s\n' "$imgs" | grep "sha256:$pfx")
    if [ -n "$m" ]; then
      printf '%s\n' "$m" | while IFS= read -r line; do echo "   FLAG: image $line matches a compromised digest"; done
      findings=$((findings + 1)); seen=1
    fi
  done
  [ "$seen" -eq 0 ] && note "no local image matches the compromised digests"
else
  note "docker not available, skipped"
fi

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Do not start Python in a flagged environment. Read 'If it flags something' in the README."
  exit 1
fi
echo "RESULT: nothing found."
exit 0
