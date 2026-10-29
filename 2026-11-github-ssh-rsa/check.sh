#!/bin/sh
# breach-checks: 2026-11-github-ssh-rsa
#
# Finds SSH setups likely to break when GitHub turns off the SHA-1 "ssh-rsa"
# signature type and diffie-hellman-group-exchange-sha256: brownouts on
# Nov 4 and Dec 9, 2026, removal on Jan 13, 2027.
# Source: https://github.blog/changelog/2026-09-22-security-improvements-for-ssh/
#
# Usage: sh check.sh [--live] [folder ...]
#   folder   extra trees to search (CI repos, Dockerfiles, Jenkins home)
#   --live   also run `ssh -vT git@github.com` and show what got negotiated
#
# Read only. Never prints private key material. Exit 0 nothing found,
# 1 something to look at, 2 usage error.
#
# Test hooks: BC_SSH_V (fake `ssh -V` text), BC_SSH_CONFIGS (config files),
# BC_KEY_DIR (folder of .pub keys), BC_PLINK_V, BC_CURL_V.

set -u
live=0
dirs=""
for a in "$@"; do
  case "$a" in
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --live) live=1 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) dirs="$dirs $a" ;;
  esac
done

findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

# ver_lt A B: true if dotted version A < B
ver_lt() {
  [ "$1" = "$2" ] && return 1
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]
}

echo "== 1. OpenSSH client"
sv="${BC_SSH_V:-$(ssh -V 2>&1 || true)}"
note "${sv:-no ssh client found}"
ov=$(echo "$sv" | sed -n 's/.*OpenSSH_\([0-9]*\.[0-9]*\)p\{0,1\}\([0-9]*\).*/\1.\2/p' | head -1)
if [ -n "$ov" ]; then
  if ver_lt "$ov" "7.2.1"; then
    flag "OpenSSH $ov is older than 7.2p1, the minimum GitHub lists for RSA with SHA-2"
  fi
fi

echo "== 2. SSH config that forces the old algorithms"
cfgs="${BC_SSH_CONFIGS:-$HOME/.ssh/config /etc/ssh/ssh_config $(ls /etc/ssh/ssh_config.d/*.conf 2>/dev/null)}"
re_rsa='^[[:space:]]*(PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostKeyAlgorithms|CASignatureAlgorithms)[[:space:]=]+[^#]*(^|[=,+[:space:]])ssh-rsa(,|[[:space:]]|$)'
re_kex='^[[:space:]]*KexAlgorithms[[:space:]=]+[^#]*diffie-hellman-group-exchange-sha256'
for c in $cfgs; do
  [ -f "$c" ] || continue
  grep -nE "$re_rsa" "$c" 2>/dev/null | while IFS= read -r l; do echo "   FLAG: $c:$l  (turns SHA-1 ssh-rsa back on)"; done
  findings=$((findings + $(grep -cE "$re_rsa" "$c" 2>/dev/null || true)))
  grep -nE "$re_kex" "$c" 2>/dev/null | while IFS= read -r l; do
    case "$l" in
      *KexAlgorithms*[=\ ]+*|*KexAlgorithms\ +*) echo "   note: $c:$l (adds group exchange; fine as long as other methods remain)";;
      *) echo "   FLAG: $c:$l  (pins a kex list that includes the one being removed; make sure curve25519 or ecdh is in it too)";;
    esac
  done
  findings=$((findings + $(grep -E "$re_kex" "$c" 2>/dev/null | grep -cvE 'KexAlgorithms[[:space:]=]+\+' || true)))
done
note "searched: $(echo "$cfgs" | wc -w) config file(s)"

echo "== 3. keys"
kd="${BC_KEY_DIR:-$HOME/.ssh}"
for k in "$kd"/*.pub; do
  [ -f "$k" ] || continue
  info=$(ssh-keygen -lf "$k" 2>/dev/null) || continue
  bits=${info%% *}
  case "$info" in
    *"(RSA)"*)
      if [ "$bits" -lt 3072 ] 2>/dev/null; then
        note "$k: RSA $bits bits. Fine for existing GitHub keys if your client signs with SHA-2, but GitHub refuses new uploads under 3072 since Oct 14."
      else
        note "$k: RSA $bits bits"
      fi ;;
    *"(RSA-CERT)"*) note "$k: RSA certificate. Make sure your CA signs with rsa-sha2-256/512, not ssh-rsa (SHA-1)." ;;
    *) t=${info##*(}; note "$k: ${t%)}" ;;
  esac
done

echo "== 4. SSH libraries and tools"
pv="${BC_PLINK_V:-$(plink -V 2>/dev/null | head -1 || true)}"
if [ -n "$pv" ]; then
  v=$(echo "$pv" | sed -n 's/.*[Rr]elease \([0-9][0-9.]*\).*/\1/p')
  note "PuTTY: $pv"
  [ -n "$v" ] && ver_lt "$v" "0.82" && flag "PuTTY/plink $v is older than 0.82 (GitHub's listed minimum)"
fi
cv="${BC_CURL_V:-$(curl -V 2>/dev/null | head -1 || true)}"
l2=$(echo "$cv" | sed -n 's/.*libssh2\/\([0-9][0-9.]*\).*/\1/p')
if [ -n "$l2" ]; then
  note "curl links libssh2 $l2"
  ver_lt "$l2" "1.11.0" && flag "libssh2 $l2 is older than 1.11.0 (GitHub's listed minimum); matters if this curl or a libgit2 tool talks SSH to GitHub"
fi
for d in $dirs; do
  [ -d "$d" ] || { note "not a folder: $d"; continue; }
  echo "== 5. searching $d"
  tmp="${TMPDIR:-/tmp}/bc-sshrsa.$$"
  # Original JSch (com.jcraft) has no SHA-2 RSA. Jenkins plugins bundle it.
  grep -rnIE --include='pom.xml' --include='*.gradle' --include='*.gradle.kts' --include='*.sbt' 'com\.jcraft|jcraft.*jsch' "$d" 2>/dev/null > "$tmp"
  while IFS= read -r l; do flag "original JSch (com.jcraft): $l  (GitHub lists the com.github.mwiede fork, 0.1.66 or later)"; done < "$tmp"
  find "$d" -type f \( -name 'jsch-0.1.*.jar' -o -name 'jsch.jpi' -o -name 'jsch.hpi' \) 2>/dev/null > "$tmp"
  while IFS= read -r l; do
    case "$l" in
      *jsch-0.1.[0-9].jar|*jsch-0.1.[1-5][0-9].jar|*jsch-0.1.6[0-5].jar) flag "old JSch jar: $l" ;;
      *) note "JSch artifact, check its version: $l" ;;
    esac
  done < "$tmp"
  # Go: golang.org/x/crypto, GitHub's table says "Go SSH 0.16.0"
  grep -rnE '^[[:space:]]*golang\.org/x/crypto[[:space:]]+v0\.([0-9]|1[0-5])\.' --include='go.mod' "$d" 2>/dev/null > "$tmp"
  while IFS= read -r l; do flag "golang.org/x/crypto below v0.16.0: $l"; done < "$tmp"
  # Python paramiko: SHA-2 RSA signatures arrived in 2.9.0
  grep -rniE '^[[:space:]]*paramiko[[:space:]]*(==|<=|<)[[:space:]]*(1\.|2\.[0-8](\.|$))' --include='requirements*.txt' --include='*.in' --include='Pipfile' --include='pyproject.toml' "$d" 2>/dev/null > "$tmp"
  while IFS= read -r l; do flag "paramiko pinned below 2.9: $l"; done < "$tmp"
  # Scripts, CI files and Dockerfiles that force ssh-rsa on the command line
  grep -rnIE -- '-o[[:space:]]*"?(PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostKeyAlgorithms)=\+?ssh-rsa|(PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostKeyAlgorithms)[[:space:]]+\+?ssh-rsa' "$d" 2>/dev/null > "$tmp"
  while IFS= read -r l; do flag "forces ssh-rsa: $l"; done < "$tmp"
  # Old base images whose OpenSSH predates 7.2
  grep -rnIE '^[[:space:]]*FROM[[:space:]]+[^[:space:]]*(centos:6|ubuntu:(14\.04|12\.04)|debian:(wheezy|jessie|7|8)([[:space:]]|$)|alpine:3\.[0-3]([[:space:]]|$))' "$d" 2>/dev/null > "$tmp"
  while IFS= read -r l; do flag "base image with an OpenSSH older than 7.2: $l"; done < "$tmp"
  rm -f "$tmp"
done
[ -z "$dirs" ] && note "no folders given; pass your CI repos or Jenkins home to search them"

if [ "$live" = 1 ]; then
  echo "== 6. live handshake with github.com"
  out=$(ssh -vT -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 git@github.com 2>&1 || true)
  printf '%s\n' "$out" | grep -E 'kex: algorithm|kex: host key algorithm|Server accepts key|Authenticated to|Permission denied|successfully authenticated' | sed 's/^/   /'
  printf '%s\n' "$out" | grep -q 'kex: algorithm' || note "the handshake did not get as far as key exchange (port 22 blocked or a proxy in the way?). Try: ssh -vT -p 443 git@ssh.github.com"
  printf '%s\n' "$out" | grep -q 'kex: algorithm: diffie-hellman-group-exchange-sha256' && flag "this client negotiated diffie-hellman-group-exchange-sha256, which GitHub is removing"
  printf '%s\n' "$out" | grep -qE 'Server accepts key: .* ssh-rsa ' && flag "this client signed with ssh-rsa (SHA-1)"
fi

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Fix these before Nov 4, or expect failures that day."
  exit 1
fi
echo "RESULT: nothing found. Also run this inside each CI image and on each Jenkins agent."
exit 0
