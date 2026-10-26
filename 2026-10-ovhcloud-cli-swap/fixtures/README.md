# Fixtures

None of these files are malware. Nobody outside the attacker has a copy of the
swapped binaries, so the tests use stand-ins.

- `swapped-lookalike/main.go` is a tiny Go program. `test.sh` builds it with
  `-ldflags="-s -w"` and it contains the commit id `5ead8ef9b43d...` as a
  string, so it carries the same two fingerprints as the swapped build.
- `clean-build/main.go` is a tiny Go program built with no extra flags.
- `tmp-with-stage/` holds an `envchecker-` folder with ten digits, like the
  ones the stealer leaves behind.
- `tmp-decoy/` holds folders that look close but should not match.
- `tmp-clean/` is empty.

The MD5 match path is tested by adding the MD5 of a fixture file to the bad
list through `BC_EXTRA_BAD_MD5`, because we cannot produce a file with one of
the real bad hashes. The exposure window check is tested the same way through
`BC_WINDOW_START` and `BC_WINDOW_END`, because a file's change time cannot be
set by hand.
