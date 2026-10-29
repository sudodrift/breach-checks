# breach-checks

Small, read-only shell scripts that check your own machines for one specific
security incident each. Every folder matches an article on
[sudodrift.github.io](https://sudodrift.github.io) that explains what happened
and what to do.

Every script:

- only reads files. It never runs a suspect binary and never starts an
  interpreter that could set off a payload.
- never sends data anywhere. No network calls.
- is plain POSIX `sh`, tested on Linux with dash, bash in POSIX mode and
  BusyBox, and written to work on macOS where the incident affects macOS.
- exits 0 when nothing is found, 1 when something needs a look, 2 on a usage
  error.

## Checks

| Check | What it looks for | Article |
| --- | --- | --- |
| [2026-10-ovhcloud-cli-swap](2026-10-ovhcloud-cli-swap/) | Swapped `ovhcloud` binaries from October 19, 2026, by MD5, build info and commit id, plus leftover `envchecker-` folders | [The OVHcloud CLI Was Swapped for a Stealer, and the Checksums Still Matched](https://sudodrift.github.io/posts/ovhcloud-cli-swap/) |
| [2026-10-litellm-1.107.0](2026-10-litellm-1.107.0/) | litellm 1.107.0 in pip, venv, uv, pipx and conda installs, caches and lockfiles, the `cook.pth` startup hook, and marker files | [The LiteLLM Hack Started With a Key Nobody Revoked in May](https://sudodrift.github.io/posts/litellm-key-nobody-revoked/) |
| [2026-10-warp-trace-check](2026-10-warp-trace-check/) | Masked list of keys sitting in Warp's local agent prompts, conversations, session blocks and MCP config, plus its privacy settings (Python, standard library) | [Warp lost some agent traces. Here is how I would find the keys that were in mine.](https://sudodrift.github.io/posts/warp-agent-traces/) |
| [2026-10-gitee-two-scanners](2026-10-gitee-two-scanners/) | Runs TruffleHog and Kingfisher over one repo's full git history, merges what they find (masked) and shows which tool caught each key and which sit in deleted files (Python, standard library) | [26,400 working keys were sitting in public Gitee repos. One scanner would have caught about half.](https://sudodrift.github.io/posts/gitee-keys-two-scanners/) |
| [2026-10-hosting-ai-keys](2026-10-hosting-ai-keys/) | A masked inventory of AI and other API keys in env files and configs, so you know what to rotate after the Zeabur, OpenCode and Railway incidents | [Someone Spent a Week Raiding Hosting Platforms for AI Keys. Here's How to Check Yours](https://sudodrift.github.io/posts/ai-keys-hosting-platforms/) |
| [2026-10-php2shell](2026-10-php2shell/) | Unfixed PHP builds for CVE-2026-109618/109619, crash/OOM log lines, web users spawning shells, recently modified PHP in web roots; stage2.sh for the Fragnesia root chain (kernel, PAM page-cache rewrite, tunnels, tiny webshells) | [Your firewall is a Linux box. Check it before Oct 31.](https://sudodrift.github.io/posts/firewall-linux-box/) |
| [2026-11-github-ssh-rsa](2026-11-github-ssh-rsa/) | Old OpenSSH, configs that re-enable ssh-rsa, short RSA keys, PuTTY/libssh2/JSch/paramiko/golang.org/x/crypto and Dockerfiles that will break on GitHub's Nov 4 / Dec 9 brownouts | Will your CI break on Nov 4? (draft) |

## How to use one

Read the script first. They are short on purpose. Then run it:

```sh
git clone https://github.com/sudodrift/breach-checks
cd breach-checks/2026-10-litellm-1.107.0
less check.sh
sh check.sh
```

Each folder's README says what happened, what the script checks, what a clean
result does not prove, and what to do if it flags something.

## Tests

```sh
make test   # runs every check against its fixtures
make lint   # shellcheck on every script
```

Fixtures are harmless stand-ins. Each folder's `fixtures/README.md` says what
they are.

## Get the next one

A new check goes up when a new article does. To get one breach a week with the
fix that goes with it, subscribe to
[Weekly Breach Notes](https://weeklybreachnotes.substack.com).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Corrections to facts are the most
welcome kind of pull request. Please include the primary source.

## License

MIT. See [LICENSE](LICENSE).
