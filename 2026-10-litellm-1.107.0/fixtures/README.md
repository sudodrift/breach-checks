# Fixtures

Every file here ends in `.fixture` so that running `check.sh` over your home
folder does not flag this repository. `test.sh` copies them into a temporary
folder with their real names and layout before each test.

- `cook.pth.fixture` and `cook-crlf.pth.fixture` contain the single line
  `import cook` with LF and CRLF line endings. Their SHA-256 values are exactly
  the two `cook.pth` hashes in the Microsoft IOC table
  (`7f191632...` and `84dc8c82...`), so the hash match path is tested with the
  real indicator. The line is harmless on its own.
- `cook.py.fixture` is a one-line comment. It stands in for the stealer and
  contains no code.
- `sitecustomize-distro.py.fixture` looks like the `sitecustomize.py` that
  Debian and Ubuntu ship. It must not be flagged.
- `METADATA-*.fixture` go into `litellm-<version>.dist-info` folders.
- `requirements-*`, `uv-bad.lock`, `poetry-good.lock` and `Pipfile-bad.lock`
  cover lockfile parsing, including near misses such as another package at
  version 1.107.0 and `litellm-helper==1.107.0`.
