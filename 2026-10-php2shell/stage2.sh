#!/bin/sh
# breach-checks: 2026-10-php2shell, stage 2 (Fragnesia, CVE-2026-46300)
#
# Stage 1 (check.sh) asks "could PHP2Shell get in". Stage 2 asks "if it did,
# did it get root and stay". It follows the chain Dream Research described on
# October 26, 2026: PHP2Shell for a shell as nobody, Fragnesia to rewrite
# /etc/pam.d/su to pam_permit.so, a tiny PHP webshell, and a reverse SSH
# tunnel kept alive by systemd and rc.local.
#
# Read only. Run it as root BEFORE you reboot or drop caches. Fragnesia
# changes the in-memory (page cache) copy of a file, so a reboot wipes the
# evidence. The webshell and the tunnel are on disk and survive.
#
# Usage: sudo sh stage2.sh
# Exit codes: 0 nothing found, 1 something to look at, 2 usage error.
#
# Test hooks (used by test-stage2.sh):
#   BC_ROOT          prefix for /etc, /boot, /lib and web roots (default "")
#   BC_UNAME_R       running kernel release instead of `uname -r`
#   BC_KERNELS       space separated installed kernel releases
#   BC_KCHANGELOG    file to grep for CVE-2026-46300 instead of the distro changelog
#   BC_LSMOD         file standing in for /proc/modules
#   BC_PROC_LIST     file standing in for `ps -eo user,pid,ppid,args`
#   BC_VERIFY_OUT    file standing in for dpkg --verify / rpm -V output
#   BC_NO_DIRECT     set to 1 to skip the O_DIRECT page cache comparison
#   BC_WEB_ROOTS     web roots to search for tiny PHP files

set -u
case "${1:-}" in
  -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  -*) echo "unknown option: $1" >&2; exit 2 ;;
esac

R="${BC_ROOT:-}"
findings=0
flag() { echo "   FLAG: $*"; findings=$((findings + 1)); }
note() { echo "   $*"; }

# Upstream stable releases that carry the fix, from the CVE-2026-46300 record.
# Distro kernels backport, so the changelog check below is the better signal.
FIXED_UPSTREAM="5.10.257 5.15.208 6.1.174 6.6.141 6.12.91 6.18.33 7.0.10"

ver_ge() { # $1 >= $2, dotted numbers
  # shellcheck disable=SC2046
  set -- $(echo "$1" | tr '.' ' ') $(echo "$2" | tr '.' ' ')
  [ "${1:-0}" -gt "${4:-0}" ] && return 0; [ "${1:-0}" -lt "${4:-0}" ] && return 1
  [ "${2:-0}" -gt "${5:-0}" ] && return 0; [ "${2:-0}" -lt "${5:-0}" ] && return 1
  [ "${3:-0}" -ge "${6:-0}" ]
}

echo "== 0. before you go on"
note "Do not reboot, drop caches or run the vendor cleanup yet. Read this output first."
[ "$(id -u 2>/dev/null || echo 0)" = 0 ] || [ -n "$R" ] || note "not root: some checks below will be skipped or incomplete"

echo "== 1. running kernel vs installed kernel"
running="${BC_UNAME_R:-$(uname -r)}"
note "running: $running"
installed="${BC_KERNELS:-}"
if [ -z "$installed" ]; then
  for f in "$R"/boot/vmlinuz-*; do [ -e "$f" ] && installed="$installed ${f##*/vmlinuz-}"; done
fi
newest=$(for k in $installed; do echo "$k"; done | sort -V | tail -1)
if [ -n "$newest" ]; then
  note "newest installed: $newest"
  if [ "$newest" != "$running" ] && [ "$(printf '%s\n%s\n' "$running" "$newest" | sort -V | tail -1)" = "$newest" ]; then
    flag "a newer kernel ($newest) is installed but not running. If that is your fix, it is not active until a reboot (do the checks below first)."
  fi
else
  note "could not list installed kernels from /boot"
fi
cl="${BC_KCHANGELOG:-}"
if [ -z "$cl" ]; then
  for c in "$R/usr/share/doc/linux-modules-$running/changelog.Debian.gz" "$R/usr/share/doc/linux-image-$running/changelog.Debian.gz"; do
    [ -f "$c" ] && cl=$c && break
  done
fi
if [ -n "$cl" ] && [ -f "$cl" ]; then
  if (zcat -f "$cl" 2>/dev/null || cat "$cl") | grep -q 'CVE-2026-46300'; then
    note "running kernel changelog mentions CVE-2026-46300 (fixed)"
  else
    flag "running kernel changelog does not mention CVE-2026-46300"
  fi
elif [ -z "$R" ] && command -v rpm >/dev/null 2>&1 && rpm -q "kernel-core-$running" >/dev/null 2>&1; then
  if rpm -q --changelog "kernel-core-$running" 2>/dev/null | grep -q 'CVE-2026-46300'; then
    note "running kernel changelog mentions CVE-2026-46300 (fixed)"
  else
    flag "running kernel changelog does not mention CVE-2026-46300"
  fi
else
  base=$(echo "$running" | sed -n 's/^\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p')
  mm=$(echo "$base" | cut -d. -f1,2)
  hit=""
  for fx in $FIXED_UPSTREAM; do
    [ "$(echo "$fx" | cut -d. -f1,2)" = "$mm" ] && hit=$fx
  done
  if [ -n "$hit" ] && ver_ge "$base" "$hit"; then
    note "upstream version $base is at or above the fixed stable release $hit"
  elif [ -n "$hit" ]; then
    flag "upstream version $base is below the fixed stable release $hit (ignore if your vendor backported the fix; check its advisory)"
  else
    note "no distro changelog found and $base is not a tracked stable branch. Check your vendor's advisory for CVE-2026-46300."
  fi
fi

echo "== 2. esp4 / esp6 / rxrpc module block"
blocked=""
for m in esp4 esp6 rxrpc; do
  if grep -qsE "^[[:space:]]*(install[[:space:]]+${m}[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+$m)" \
       "$R"/etc/modprobe.d/*.conf "$R"/lib/modprobe.d/*.conf "$R"/usr/lib/modprobe.d/*.conf >/dev/null 2>&1; then
    blocked="$blocked $m"
  fi
done
note "blocked in modprobe.d:${blocked:- none}"
mods="${BC_LSMOD:-/proc/modules}"
loaded=""
[ -r "$mods" ] && for m in esp4 esp6 rxrpc; do grep -q "^$m " "$mods" && loaded="$loaded $m"; done
note "loaded now:${loaded:- none}"
[ -n "$loaded" ] && flag "loaded:$loaded. If you do not use IPsec or AFS, these should not be loaded on an unpatched kernel."
case "$blocked" in *esp4*esp6*) ;; *) note "esp4/esp6 not both blocked. That is fine on a fixed kernel; on an unfixed one the block is the stopgap distros published." ;; esac

echo "== 3. PAM files: memory copy vs disk copy"
pamfiles="$R/etc/pam.d/su $R/etc/pam.d/su-l $R/etc/pam.d/sudo $R/etc/pam.d/login $R/etc/pam.d/sshd $R/etc/pam.d/system-auth $R/etc/pam.d/common-auth"
if [ "${BC_NO_DIRECT:-0}" = 1 ]; then
  note "skipped (BC_NO_DIRECT=1)"
else
  for f in $pamfiles; do
    [ -f "$f" ] || continue
    if ! dd if="$f" iflag=direct bs=4096 status=none 2>/dev/null >/dev/null; then
      note "$f: O_DIRECT read not supported here, cannot compare"
      continue
    fi
    # dd with iflag=direct and a block size larger than the file still reads it whole
    if ! dd if="$f" iflag=direct bs=1M status=none 2>/dev/null | cmp -s - "$f"; then
      flag "$f differs between page cache and disk. Copy it now with: cat $f > /root/evidence-$(basename "$f")"
    fi
  done
  note "compared what was readable (no FLAG lines above means they match)"
fi

echo "== 4. pam_permit as sufficient"
for f in $pamfiles; do
  [ -f "$f" ] || continue
  if grep -qE '^[[:space:]]*auth[[:space:]]+(sufficient|\[success=done[^]]*\])[[:space:]]+pam_permit' "$f"; then
    flag "$f lets pam_permit satisfy auth. That is the backdoor from the Dream write-up."
  fi
done
note "('auth required pam_permit.so' in Debian's common-auth is normal)"

echo "== 5. PAM files against the package"
vout="${BC_VERIFY_OUT:-}"
tmpv="${TMPDIR:-/tmp}/bc-stage2-verify.$$"
if [ -n "$vout" ]; then
  cp "$vout" "$tmpv"
elif command -v dpkg >/dev/null 2>&1 && [ -z "$R" ]; then
  dpkg --verify libpam-runtime libpam-modules libpam-modules-bin login util-linux sudo openssh-server 2>/dev/null > "$tmpv"
elif command -v rpm >/dev/null 2>&1 && [ -z "$R" ]; then
  rpm -V pam util-linux sudo openssh-server 2>/dev/null > "$tmpv"
else
  : > "$tmpv"
  note "no dpkg or rpm here; compare /etc/pam.d against a known-good image instead"
fi
# Minimal images often drop man pages and docs; those are not interesting.
grep -vE '/usr/share/(man|doc|locale)/' "$tmpv" > "$tmpv.f" 2>/dev/null; mv "$tmpv.f" "$tmpv"
grep -E '/etc/pam\.d/|pam_permit|/(usr/)?bin/su$|/(usr/)?bin/sudo$|pam_unix' "$tmpv" 2>/dev/null | while IFS= read -r l; do
  echo "   FLAG: package verify: $l"
done
n=$(grep -cE '/etc/pam\.d/|pam_permit|/(usr/)?bin/su$|/(usr/)?bin/sudo$|pam_unix' "$tmpv" 2>/dev/null || true)
findings=$((findings + ${n:-0}))
[ "${n:-0}" -eq 0 ] && note "no PAM, su or sudo files reported as changed by the package manager"
note "(on a live box this reads through the page cache, so it also catches a memory-only rewrite until reboot)"
rm -f "$tmpv"

echo "== 6. reverse tunnels and SOCKS proxies that start on their own"
tun='ssh[^#]*[[:space:]]-[a-zA-Z]*[RD][[:space:]]|autossh|(^|[/[:space:]])iox([[:space:]]|$)|socks5?://|-o[[:space:]]*RemoteForward|DynamicForward'
for d in "$R/etc/systemd/system" "$R/usr/lib/systemd/system" "$R/lib/systemd/system" "$R/run/systemd/system" "$R/etc/init.d"; do
  [ -d "$d" ] || continue
  grep -rlEs "$tun" "$d" 2>/dev/null | while IFS= read -r f; do echo "   FLAG: unit or init script with a tunnel command: $f"; done
done
for f in "$R/etc/rc.local" "$R/etc/rc.d/rc.local" "$R/etc/crontab" "$R"/etc/cron.d/* "$R"/var/spool/cron/* "$R"/var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  grep -Eqs "$tun" "$f" && echo "   FLAG: tunnel command in $f"
done
c=0
for d in "$R/etc/systemd/system" "$R/usr/lib/systemd/system" "$R/lib/systemd/system" "$R/run/systemd/system" "$R/etc/init.d"; do
  [ -d "$d" ] && c=$((c + $(grep -rlEs "$tun" "$d" 2>/dev/null | wc -l)))
done
for f in "$R/etc/rc.local" "$R/etc/rc.d/rc.local" "$R/etc/crontab" "$R"/etc/cron.d/* "$R"/var/spool/cron/* "$R"/var/spool/cron/crontabs/*; do
  [ -f "$f" ] && grep -Eqs "$tun" "$f" && c=$((c + 1))
done
findings=$((findings + c))
if [ -n "${BC_PROC_LIST:-}" ] && [ -f "$BC_PROC_LIST" ]; then proc=$(cat "$BC_PROC_LIST"); else proc=$(ps -eo user,pid,ppid,args 2>/dev/null || true); fi
p=$(printf '%s\n' "$proc" | grep -E "$tun" | grep -v grep || true)
if [ -n "$p" ]; then
  printf '%s\n' "$p" | while IFS= read -r l; do echo "   FLAG: running tunnel: $l"; done
  findings=$((findings + $(printf '%s\n' "$p" | wc -l)))
fi
[ "$c" -eq 0 ] && [ -z "$p" ] && note "no ssh -R / -D, autossh or iox in units, rc.local, cron or the process list"

echo "== 7. tiny PHP files in web roots"
roots="${BC_WEB_ROOTS:-$R/var/www $R/srv/www $R/usr/share/nginx/html $R/var/appweb}"
t=0
for root in $roots; do
  [ -d "$root" ] || continue
  tl="${TMPDIR:-/tmp}/bc-stage2-php.$$"
  find "$root" -type f -name '*.php' -size -400c 2>/dev/null > "$tl"
  while IFS= read -r f; do
    # shellcheck disable=SC2016
    if grep -qsE 'system|exec|passthru|shell_exec|popen|proc_open|eval|assert|`' "$f" && grep -qsE '\$_(GET|POST|REQUEST|COOKIE|SERVER)' "$f"; then
      flag "small PHP file that runs request input: $f ($(wc -c < "$f") bytes)"
      t=$((t + 1))
    fi
  done < "$tl"
  rm -f "$tl"
done
[ "$t" -eq 0 ] && note "no small PHP files that pass request input to a command function"

echo
if [ "$findings" -gt 0 ]; then
  echo "RESULT: $findings finding(s). Keep the box up, save the flagged files, and read 'Stage 2' in the README."
  exit 1
fi
echo "RESULT: nothing found by stage 2."
exit 0
