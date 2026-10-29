# php2shell (October 21, 2026)

Article: [Was I Hit by the PHP2Shell Bugs?](https://sudodrift.github.io/posts/php2shell-was-i-hit/)

## What happened

On October 21, 2026 the PHP project released emergency fixes for two critical
remote code execution bugs, [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
together called php2shell. [CISA](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
urges immediate patching of every PHP install that serves web requests
(Apache mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed) and added both CVEs
to its KEV catalog on October 26. Fixed upstream releases are 8.5.12, 8.4.27,
8.3.36 and 8.2.35. PHP 8.1 and earlier are outside regular upstream support.

## What the script checks

1. PHP version(s) and SAPI from `php -v` / `PHP_SAPI` (and common packaged
   php-fpm paths), and whether the build meets the fixed release for its branch.
2. Readable web and PHP error logs for Datadog's documented signals: memory
   exhaustion `in Unknown on line 0`, and Apache `AH00052` segmentation faults.
3. The process list for `www-data`, `apache`, `nginx` or php-fpm users
   spawning shells or download tools.
4. auditd / journal lines for the same shape, when those tools are present.
5. `.php` files under the usual web roots modified in the last 7 days.

It only reads files and process listings. It never runs a PoC and never starts
PHP for a web request.

## How to run it

```sh
sh check.sh
```

Exit code 0 means nothing found, 1 means something was flagged, 2 means a usage error.

Example against an unfixed fake binary:

```
== PHP version and SAPI
== /workspace/breach-checks/2026-10-php2shell/fixtures/phpbins/php-unfixed
   php -v: PHP 8.4.20 (cli) (built: Oct 1 2026)
   SAPI: cli
   FLAG: PHP 8.4.20 is below the fixed release for its branch (need 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor backport)
== crash and memory-exhaustion lines in logs
   no matching crash or OOM-before-script lines in readable logs
== web users spawning shells
   no web/php user shell or downloader processes seen in the process list
   no extra audit/journal shell or segfault hits (or tools not available)
== recently modified PHP files in web roots
   no .php files modified in the last 7 days under the usual web roots

RESULT: 1 finding(s). Read 'If it flags something' in the README.
```

## Limits

A clean result does not prove the box was never hit. Logs rotate, shells exit,
and a patched package can still leave an old worker running until you restart
it. Vendor backports may keep an older upstream version string; check your
distro advisory when the script flags a package you already updated.

## If it flags something

1. Confirm the running web SAPI (FPM pool, mod_php, cgi) and restart workers
   after you install a fixed package.
2. Treat a web user spawning a shell as a compromise until proven otherwise:
   isolate the host, keep volatile evidence, and rotate credentials the app
   could reach.
3. Review recently modified PHP files in the web root and remove anything you
   did not deploy.
4. Follow CISA and your distro advisory for the patch itself. Updating is the
   only complete fix; temporary ini tweaks only reduce some paths.

## Sources

- CISA, Critical Vulnerabilities in PHP Require Immediate Patching: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- PHP GHSA-w8hw-w9fx-j79w (CVE-2026-109618) and GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- Datadog Security Labs, PHP2Shell detection signals: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/

## Stage 2: did it get root? (Fragnesia, CVE-2026-46300)

On October 26 Dream Research
[described](https://dreamgroup.com/blog/chained-php2shell-exploit-roots-25-servers)
a crew that used PHP2Shell to get a shell as `nobody` on firewall appliances,
then the Linux kernel bug Fragnesia (CVE-2026-46300) to rewrite
`/etc/pam.d/su` to `pam_permit.so`, planted a 103-byte PHP webshell, and on
one target kept a reverse SSH tunnel alive with a systemd service and an
`rc.local` hook. CISA added Fragnesia to KEV on October 28 with a due date of
October 31 and a forensic triage flag.

`stage2.sh` looks for that chain. Run it as root, and run it **before** you
reboot or drop caches: Fragnesia edits the in-memory copy of a file, so a
reboot clears the evidence (the webshell and tunnel stay on disk).

```sh
sudo sh stage2.sh
```

It checks:

1. Running kernel against the newest installed one, and whether the running
   kernel's changelog mentions CVE-2026-46300 (Debian/Ubuntu doc changelog or
   `rpm -q --changelog`). Without a changelog it compares against the fixed
   upstream stable releases in the CVE record (5.10.257, 5.15.208, 6.1.174,
   6.6.141, 6.12.91, 6.18.33, 7.0.10).
2. Whether `esp4`, `esp6` and `rxrpc` are blocked in `modprobe.d` and whether
   they are loaded now.
3. Each PAM file read normally (page cache) against an `O_DIRECT` read (disk).
4. `auth sufficient pam_permit` in su, sudo, login, sshd and friends.
5. `dpkg --verify` or `rpm -V` for PAM, su, sudo and sshd packages.
6. `ssh -R`, `ssh -D`, autossh and iox in systemd units, init scripts,
   `rc.local`, cron and the process list.
7. PHP files under 400 bytes in web roots that pass request input to a
   command function.

It reads only. It never loads or unloads modules and never changes PAM.
Tests: `sh test-stage2.sh`.

### If stage 2 flags something

Don't reboot. Copy the flagged files with `cat` to somewhere off the box,
capture memory if you can, and treat the machine as rooted: rebuild it from a
known-good image, then rotate every secret it held (admin, VPN, the AD
service account it binds with). On an appliance you cannot shell into, ask
the vendor for their integrity check instead.
