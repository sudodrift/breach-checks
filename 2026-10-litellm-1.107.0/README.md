# LiteLLM 1.107.0 (October 21, 2026)

Article: [The LiteLLM Hack Started With a Key Nobody Revoked in May](https://sudodrift.github.io/posts/litellm-key-nobody-revoked/)

## What happened

On October 21, 2026, LiteLLM's release pipeline published a malicious `litellm==1.107.0` to PyPI, live from 11:39 to 13:23 UTC, and pointed the Docker tags `v1.107.0`, `latest`, `main-latest` and `main-stable` at a bad image until 14:20 UTC ([LiteLLM incident post](https://docs.litellm.ai/blog/security-incident-oct-21-2026)). All seven wheels carried three extra files, `cook.pth`, `cook.py` and `sitecustomize.py`, which pip installs at the top of site-packages, so the payload runs every time Python starts in that environment, pip included, even if nothing imports litellm ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144)). `cook.py` is a credential stealer that sends its haul to `www.litellm.dev`, and `sitecustomize.py` starts a background loader that holds `/tmp/remote_code_loader.lock` and can fetch more code ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)). LiteLLM's root cause post says a master key committed to a public repository on May 27 was never revoked, and the attacker used it on October 10 to get a GitHub organization owner's CLI token, then later repointed the release workflow at a lookalike fork, `Berri-AI/litellm` ([LiteLLM root cause](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain)). LiteLLM says to pin `1.106.2` or another version published before the incident.

## What the script checks

It never starts Python. It only uses `find`, `grep`, `awk` and a SHA-256 tool, because any Python start in a bad environment runs the payload again.

1. Installed litellm versions, from `litellm-*.dist-info` and `litellm-*.egg-info` folders (pip, venv, uv, pipx, Poetry, system Python) and `conda-meta/litellm-*.json` (conda). It lists every version it finds and flags 1.107.0. It also flags 1.82.7 and 1.82.8, the March 2026 releases listed in the same OSV entry.
2. `cook.pth`, `cook.py` and `sitecustomize.py`. Each is hashed and compared with the published IOC hashes. `cook.pth` or `cook.py` at the top of a site-packages folder is flagged even without a hash match. A `sitecustomize.py` without a hash match is only listed, because Debian and Ubuntu ship one for the system Python.
3. `cook.*.pyc` in the `__pycache__` folder at the top of site-packages.
4. Cached `litellm-*.whl` files (hashed against the seven published wheel hashes) and 1.107.0 entries in the uv and pip caches.
5. Lockfiles that pin 1.107.0: `requirements*.txt`, `constraints*.txt`, `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock*.toml` and `Pipfile.lock`.
6. The files the payload leaves in `/tmp`: `.pc_once_72129118c59f5636c0bb` (written after a successful upload), `remote_code_loader.lock` (the loader), and `.pc_e_*` / `.pc_sq_*` folders. If `fuser` is present it shows which process holds the lock.
7. If Docker is installed and running, local images whose digest starts with one of the three compromised image indexes from LiteLLM's post (`1bbcb1443bc9`, `c00f9d92c427`, `7b00e91cd2fe`).

By default it searches `$HOME`, `/usr/lib`, `/usr/local/lib`, `/usr/lib64`, `/opt`, and on macOS `/Library/Frameworks/Python.framework`, `/opt/homebrew/lib` and `/usr/local/Cellar`. It skips `/proc`, `/sys`, `/dev`, `.git` and `node_modules`. Works on Linux and macOS.

## How to run it

```sh
sh check.sh                        # search the default places
sh check.sh ~/code /srv/app        # search these folders instead (lockfiles included)
```

Exit code 0 means nothing found, 1 means something was flagged, 2 means a usage error.

Real output against a virtualenv with the clean 1.106.2 installed from PyPI:

```
$ BC_NO_DOCKER=1 sh check.sh /tmp/litedemo
== installed litellm versions (dist-info, egg-info, conda-meta)
   litellm 1.106.2 at /tmp/litedemo/.venv/lib/python3.13/site-packages/litellm-1.106.2.dist-info
== startup hook files (cook.pth, cook.py, sitecustomize.py)
   none found
== cached wheels
   none found
== lockfiles and requirements pinning 1.107.0
   none found
== marker and lock files
   none found (containers and tmp cleaners remove these, so this alone proves nothing)
== local Docker images
   skipped

RESULT: nothing found.
```

Real output against a tree built from the test fixtures (see `fixtures/README.md`). The `cook.pth` fixture is the one line `import cook`, whose SHA-256 is the published IOC; the `cook.py` fixture is a harmless comment:

```
$ BC_NO_DOCKER=1 sh check.sh /tmp/litefx
== installed litellm versions (dist-info, egg-info, conda-meta)
   FLAG: litellm 1.107.0 at /tmp/litefx/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info
== startup hook files (cook.pth, cook.py, sitecustomize.py)
   FLAG: /tmp/litefx/.venv/lib/python3.12/site-packages/cook.pth sha256 matches a published IOC
   FLAG: /tmp/litefx/.venv/lib/python3.12/site-packages/cook.py sits at the top of /tmp/litefx/.venv/lib/python3.12/site-packages (where the payload installs itself)
== cached wheels
   none found
== lockfiles and requirements pinning 1.107.0
   FLAG: /tmp/litefx/uv.lock locks litellm 1.107.0
== marker and lock files
   none found (containers and tmp cleaners remove these, so this alone proves nothing)
== local Docker images
   skipped

RESULT: 4 finding(s). Do not start Python in a flagged environment. Read 'If it flags something' in the README.
```

## Limits

- A missing marker file proves nothing. Containers and tmp cleaners remove them, and `.pc_once_...` is only written after a successful upload.
- It cannot look inside container images or remote registries. Use the digests above with `docker images --digests` or your registry's tools, and check internal mirrors (Artifactory, Nexus, devpi) yourself.
- Only the versions and hashes listed above are known. A new release with a different payload would not match.

## If it flags something

1. Do not run `python`, `pip` or anything else that starts the affected interpreter.
2. From the shell, delete `cook.pth`, `cook.py`, the matching `__pycache__/cook*.pyc`, and `sitecustomize.py` plus `__pycache__/sitecustomize*.pyc` only if its hash matched, from every affected site-packages folder.
3. Stop the background loader: find the process that holds `/tmp/remote_code_loader.lock` (`fuser` or `lsof`) and kill it.
4. Rebuild the virtualenv or image from scratch with `litellm==1.106.2` pinned. Rebuilding is safer than patching.
5. From another machine, rotate everything the host could reach: the instance or task role, every provider key stored in the LiteLLM proxy database, the master and virtual keys, the `DATABASE_URL` password, and any secret in the environment of any process on the host. JFrog's and Microsoft's write ups list the rest of what the stealer reads (SSH and GPG keys, cloud credentials, browser data, AI tool configs).
6. On AWS, LiteLLM suggests looking in CloudTrail for `GetCallerIdentity` from the instance role around install time, then for use of that role from outside your network. Check DNS and proxy logs for `litellm.dev`.

## Sources

- LiteLLM, incident post for v1.107.0: https://docs.litellm.ai/blog/security-incident-oct-21-2026
- LiteLLM, attack chain and root cause: https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain
- OSV, MAL-2026-2144: https://osv.dev/vulnerability/MAL-2026-2144
- Microsoft Security Blog, IOC table with file and wheel hashes: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
- JFrog Security Research, marker and temp file names: https://research.jfrog.com/post/litellm-hijacked-again/
