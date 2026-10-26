# OVHcloud CLI release swap (October 19, 2026)

Article: [The OVHcloud CLI Was Swapped for a Stealer, and the Checksums Still Matched](https://sudodrift.github.io/posts/ovhcloud-cli-swap/)

## What happened

On October 19, 2026, a compromised OVHcloud developer GitHub account replaced the release files of `ovhcloud-cli` v0.11.0 to v0.15.0 with malicious builds between 14:47 and 16:21 UTC+2 (12:47 to 14:21 UTC), according to OVHcloud's advisory [GHSA-862f-55f5-vmvw](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw). Only people who installed or updated in that window are affected; the source code and build chain were not touched, and v0.10.0 and older plus v0.16.0 and newer are clean. Each run of the swapped binary copied credentials (cloud keys, SSH keys, Kubernetes and Docker config, AI coding tool data and more) into a folder named `envchecker-` plus 9 or 10 digits in the temp folder, which it never deletes, and sent an archive to `45.32.148[.]174`. OVHcloud says the repository did not have release immutability turned on, and traces the account compromise to a malicious VS Code extension installed on the developer's personal laptop in October 2025. StepSecurity, working from the customer report in [issue #300](https://github.com/ovh/ovhcloud-cli/issues/300), reports that `checksums.txt` was replaced too, so the hash file on the release page matched the bad files ([StepSecurity](https://www.stepsecurity.io/blog/ovhcloud-cli-github-release-swap-glassworm)).

## What the script checks

The script never runs `ovhcloud`. It only reads files.

1. The MD5 of each `ovhcloud` binary it finds, against the five MD5 values in the advisory appendix.
2. The file's change time (ctime). A ctime inside 12:47 to 14:21 UTC on October 19 means the file landed on disk during the window. It uses ctime because tar keeps the archive's original time as mtime.
3. A byte search of the binary for `5ead8ef9b43d`, the commit the swapped build was made from (`vcs.revision` in the advisory). This works without Go.
4. If Go is installed, `go version -m`, which reads the build info embedded in the file without running it. It prints the module line and flags `-ldflags="-s -w"`, which the advisory shows for the swapped build. The genuine v0.16.0 binary has no ldflags line at all (checked with `go version -m` on the file from the release page).
5. `envchecker-` folders with 9 or 10 digits in `/tmp` and `$TMPDIR` (macOS keeps its temp folder in `$TMPDIR`).

It does not flag a binary for `+dirty` or `vcs.modified=true`. The genuine v0.16.0 shows those too.

Where it looks by default: `ovhcloud` on your PATH, `~/.local/bin`, `/usr/local/bin`, `/usr/bin`, `/opt/homebrew/bin`, `~/go/bin` and `~/bin`. Works on Linux and macOS.

## How to run it

```sh
sh check.sh                      # look in the usual places
sh check.sh /path/to/ovhcloud    # check a specific file
```

Exit code 0 means nothing found, 1 means something was flagged, 2 means a usage error.

Real output on a Linux box against the genuine v0.16.0 binary, downloaded from the release page (archive SHA-256 `527fb1c9bde0680837601e08bc064783b57eb301ab5a81fb9c1fc17f466f2898`):

```
$ sh check.sh /tmp/ovhdemo/ovhcloud
== /tmp/ovhdemo/ovhcloud
   md5 36f459b73b8e96f39362cbc62b23c9fe is not on the advisory's bad list
   ctime 2026-10-26 16:37:13 UTC, outside the exposure window
   module: github.com/ovh/ovhcloud-cli v0.16.0+dirty
== staging folders (envchecker-*)
   none found (a reboot or tmp cleaner may have removed them, so this alone proves nothing)

RESULT: nothing found.
```

Real output against the test fixture, a harmless Go program built with `-ldflags="-s -w"` that carries the commit id as a string (see `fixtures/README.md`):

```
$ BC_TMPDIRS="$PWD/fixtures/tmp-with-stage" sh check.sh /tmp/ovhfx/ovhcloud
== /tmp/ovhfx/ovhcloud
   md5 c82d006442ec5ff3787e913a3a3d5681 is not on the advisory's bad list
   ctime 2026-10-26 16:38:03 UTC, outside the exposure window
   FLAG: binary contains commit 5ead8ef9b43d (the commit the swapped build came from)
   FLAG: built with -ldflags="-s -w", the same build flags the advisory shows for the swapped binary
== staging folders (envchecker-*)
   FLAG: staging folder /workspace/breach-checks/2026-10-ovhcloud-cli-swap/fixtures/tmp-with-stage/envchecker-1792414999 exists (the stealer never deletes it)

RESULT: 3 finding(s). Read the README section 'If it flags something'.
```

## Limits

- An MD5 list only catches those exact files. The build info and commit checks catch the pattern, but a different attacker build would not match either.
- An empty `/tmp` proves nothing. Many systems clear it at boot or after a few days.
- The script cannot see copies you deleted, or CI runners that downloaded the archive and threw it away. For CI, search job logs for downloads of `releases/download/v0.11.0` to `v0.15.0` around 12:47 to 14:21 UTC on October 19.

## If it flags something

1. Do not run the binary. Every run steals again.
2. From a different, clean machine, rotate what the advisory lists as targeted: AWS, Google Cloud and Azure credentials, Kubernetes and Docker config, npm and Terraform tokens, `~/.netrc`, git credentials, SSH keys, DigitalOcean `doctl` config, and logins for AI coding tools (VS Code, Cursor, Continue, Cody, OpenCode, Hermes, Claude). Rotate your OVHcloud API keys as well. They are not on the advisory's list, but they sit on the same machine.
3. For SSH keys, remove the old public key from every server and from GitHub or GitLab, not just generate a new one.
4. Check for outbound traffic to `45.32.148.174` and to the Solana RPC hosts listed in the advisory.
5. Delete the binary and install v0.16.0 or later. You can check the archive with `gh release verify-asset v0.16.0 ovhcloud-cli_Linux_x86_64.tar.gz -R ovh/ovhcloud-cli`.
6. If you cannot be sure the machine is clean, rebuild it.

## Sources

- OVHcloud, GHSA-862f-55f5-vmvw: https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw
- StepSecurity, OVHcloud CLI Compromised via GitHub Release Swap: https://www.stepsecurity.io/blog/ovhcloud-cli-github-release-swap-glassworm
- OVHcloud CLI releases: https://github.com/ovh/ovhcloud-cli/releases
