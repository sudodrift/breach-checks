#!/bin/sh
# Tests for check.sh.
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/keys" "$work/repo/jenkins/plugins" "$work/repo/svc"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$work/keys/old" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$work/keys/new" >/dev/null
rm -f "$work/keys/old" "$work/keys/new"   # keep only the .pub files
printf 'Host github.com\n  PubkeyAcceptedAlgorithms +ssh-rsa\n  HostKeyAlgorithms +ssh-rsa\nHost *\n  KexAlgorithms diffie-hellman-group-exchange-sha256\n' > "$work/bad_config"
printf 'Host github.com\n  IdentityFile ~/.ssh/id_ed25519\n  PubkeyAcceptedAlgorithms rsa-sha2-512,ssh-ed25519\n' > "$work/good_config"
printf '<dependency><groupId>com.jcraft</groupId><artifactId>jsch</artifactId><version>0.1.55</version></dependency>\n' > "$work/repo/pom.xml"
: > "$work/repo/jenkins/plugins/jsch-0.1.55.jar"
printf 'module x\nrequire (\n\tgolang.org/x/crypto v0.14.0\n)\n' > "$work/repo/svc/go.mod"
printf 'paramiko==2.7.2\n' > "$work/repo/requirements.txt"
printf 'git clone -o HostKeyAlgorithms=+ssh-rsa x\nssh -o PubkeyAcceptedKeyTypes=+ssh-rsa git@github.com\n' > "$work/repo/deploy.sh"
printf 'FROM centos:6\n' > "$work/repo/Dockerfile"
mkdir -p "$work/clean"; printf 'FROM debian:12\n' > "$work/clean/Dockerfile"
printf 'golang.org/x/crypto v0.31.0\n' > "$work/clean/go.mod"

run_check "bad option" sh "$here/check.sh" --nope
expect_code 2

run_check "clean" env BC_SSH_V="OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13" BC_SSH_CONFIGS="$work/good_config" \
  BC_KEY_DIR="$work/keys" BC_PLINK_V="plink: Release 0.83" BC_CURL_V="curl 8.5.0 libssh2/1.11.0" sh "$here/check.sh" "$work/clean"
expect_code 0
expect_out "RSA 2048 bits"
expect_out "ED25519"

run_check "everything old" env BC_SSH_V="OpenSSH_7.1p2, OpenSSL 1.0.1" BC_SSH_CONFIGS="$work/bad_config" \
  BC_KEY_DIR="$work/keys" BC_PLINK_V="plink: Release 0.76" BC_CURL_V="curl 7.68.0 libssh2/1.8.0" sh "$here/check.sh" "$work/repo"
expect_code 1
expect_out "OpenSSH 7.1.2 is older than 7.2p1"
expect_out "turns SHA-1 ssh-rsa back on"
expect_out "pins a kex list"
expect_out "PuTTY/plink 0.76"
expect_out "libssh2 1.8.0"
expect_out "original JSch"
expect_out "old JSch jar"
expect_out "golang.org/x/crypto below v0.16.0"
expect_out "paramiko pinned below 2.9"
expect_out "forces ssh-rsa"
expect_out "base image with an OpenSSH older than 7.2"

finish
