#!/bin/sh
# Tests for check.sh. Run from anywhere: sh test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
fx="$here/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export BC_NO_DOCKER=1
mkdir -p "$work/tmp-empty"
export BC_TMPDIRS="$work/tmp-empty"

# Build an infected venv, a clean venv, a conda env and a project folder.
sp="$work/infected/.venv/lib/python3.12/site-packages"
mkdir -p "$sp/__pycache__" "$sp/litellm-1.107.0.dist-info"
cp "$fx/cook.pth.fixture" "$sp/cook.pth"
cp "$fx/cook.py.fixture" "$sp/cook.py"
cp "$fx/METADATA-bad.fixture" "$sp/litellm-1.107.0.dist-info/METADATA"
: > "$sp/__pycache__/cook.cpython-312.pyc"
mkdir -p "$work/clean/usr/lib/python3.12/http/__pycache__"
: > "$work/clean/usr/lib/python3.12/http/__pycache__/cookies.cpython-312.pyc"
: > "$work/clean/usr/lib/python3.12/http/__pycache__/cookiejar.cpython-312.pyc"

clean="$work/clean/venv/lib/python3.11/site-packages"
mkdir -p "$clean/litellm-1.106.2.dist-info"
cp "$fx/METADATA-good.fixture" "$clean/litellm-1.106.2.dist-info/METADATA"
mkdir -p "$work/clean/usr/lib/python3.12"
cp "$fx/sitecustomize-distro.py.fixture" "$work/clean/usr/lib/python3.12/sitecustomize.py"
mkdir -p "$work/clean/proj"
cp "$fx/requirements-good.txt.fixture" "$work/clean/proj/requirements.txt"
cp "$fx/poetry-good.lock.fixture" "$work/clean/proj/poetry.lock"

mkdir -p "$work/crlf/env/Lib/site-packages"
cp "$fx/cook-crlf.pth.fixture" "$work/crlf/env/Lib/site-packages/cook.pth"

mkdir -p "$work/conda/envs/ai/conda-meta"
echo '{}' > "$work/conda/envs/ai/conda-meta/litellm-1.107.0-pyhd8ed1ab_0.json"

mkdir -p "$work/locks/a" "$work/locks/b" "$work/locks/c"
cp "$fx/requirements-bad.txt.fixture" "$work/locks/a/requirements-prod.txt"
cp "$fx/uv-bad.lock.fixture" "$work/locks/b/uv.lock"
cp "$fx/Pipfile-bad.lock.fixture" "$work/locks/c/Pipfile.lock"

mkdir -p "$work/tmp-hit/.pc_e_abc"
: > "$work/tmp-hit/.pc_once_72129118c59f5636c0bb"
: > "$work/tmp-hit/remote_code_loader.lock"

run_check "bad option" sh "$here/check.sh" --nope
expect_code 2

run_check "infected venv" sh "$here/check.sh" "$work/infected"
expect_code 1
expect_out "FLAG: litellm 1.107.0 at"
expect_out "cook.pth sha256 matches a published IOC"
expect_out "cook.py sits at the top of"
expect_out "compiled cook module"

run_check "crlf cook.pth" sh "$here/check.sh" "$work/crlf"
expect_code 1
expect_out "cook.pth sha256 matches a published IOC"

run_check "clean tree" sh "$here/check.sh" "$work/clean"
expect_code 0
expect_out "litellm 1.106.2 at"
expect_out "sitecustomize.py alone is normal"
expect_no_out "FLAG"

run_check "conda env" sh "$here/check.sh" "$work/conda"
expect_code 1
expect_out "FLAG: litellm 1.107.0 at .*conda-meta"

run_check "lockfiles" sh "$here/check.sh" "$work/locks"
expect_code 1
expect_out "requirements-prod.txt pins litellm==1.107.0"
expect_out "uv.lock locks litellm 1.107.0"
expect_out "Pipfile.lock locks litellm 1.107.0"

run_check "markers" env BC_TMPDIRS="$work/tmp-hit" sh "$here/check.sh" "$work/clean"
expect_code 1
expect_out "pc_once_72129118c59f5636c0bb exists"
expect_out "remote_code_loader.lock exists"
expect_out ".pc_e_abc exists"

# The script must never start Python. Put a fake python first on PATH that
# leaves a mark if anything calls it.
mkdir -p "$work/trap"
for name in python python3 pip pip3; do
  printf '#!/bin/sh\ntouch "%s/called"\n' "$work/trap" > "$work/trap/$name"
  chmod +x "$work/trap/$name"
done
run_check "never starts python" env PATH="$work/trap:$PATH" sh "$here/check.sh" "$work/infected"
if [ -e "$work/trap/called" ]; then bad "python or pip was called"; else ok "python and pip were not called"; fi

finish
