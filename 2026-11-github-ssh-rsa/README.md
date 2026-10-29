# github-ssh-rsa (brownouts Nov 4 and Dec 9, 2026; removal Jan 13, 2027)

Article: "Will your CI break on Nov 4?" (draft)

## What happened

On September 22, 2026 GitHub
[announced](https://github.blog/changelog/2026-09-22-security-improvements-for-ssh/)
that it is removing the `ssh-rsa` signature type (RSA with SHA-1, including
SHA-1 `ssh-rsa-cert-v01@openssh.com` certificates) and the
`diffie-hellman-group-exchange-sha256` key exchange. There are brownouts on
November 4 and December 9, 2026 and the removal is January 13, 2027. New RSA
keys must be at least 3072 bits since October 14, 2026. HTTPS remotes are not
affected. GitHub Enterprise Server gets the change in 3.25.

## What the script checks

1. The OpenSSH client version (GitHub lists 7.2p1 as the minimum).
2. `~/.ssh/config`, `/etc/ssh/ssh_config` and `ssh_config.d` for lines that
   add `ssh-rsa` back (`PubkeyAcceptedAlgorithms`, `PubkeyAcceptedKeyTypes`,
   `HostKeyAlgorithms`, `CASignatureAlgorithms`) or pin a kex list with group
   exchange.
3. Your public keys: type and size, and RSA certificates.
4. PuTTY/plink (0.82) and the libssh2 that curl links (1.11.0).
5. In any folders you pass: the original `com.jcraft` JSch in Maven or Gradle
   files, old `jsch-0.1.x.jar` files (Jenkins plugin folders), 
   `golang.org/x/crypto` below v0.16.0, paramiko pinned below 2.9, scripts
   that pass `-o ...=+ssh-rsa`, and Dockerfiles built on images old enough to
   ship OpenSSH older than 7.2.
6. With `--live`, an `ssh -vT git@github.com` handshake and the negotiated
   key exchange and signature.

It reads only and never prints private keys.

## How to run it

```sh
sh check.sh                      # this machine
sh check.sh ~/src/ci /var/lib/jenkins
sh check.sh --live               # also try a handshake with github.com
```

Run it where the SSH actually happens: inside the CI image, on each Jenkins
agent, on the build box. Your laptop passing tells you nothing about them.

Exit code 0 means nothing found, 1 means something was flagged, 2 means a
usage error.

## Limits

- Version minimums are GitHub's table. The paramiko 2.9 line comes from
  paramiko's changelog, not GitHub's table.
- A program that bundles its own SSH library will not show up. Test the real
  job on Nov 4 and have someone watching.
- Jenkins plugins that use JGit or Apache MINA SSHD, and appliances, need
  their own check.
