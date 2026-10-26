# Contributing

Thanks for helping. A few rules keep these scripts safe to run on someone
else's machine.

## Rules for every check

1. Read only. Never run the suspect binary, never start an interpreter that
   could load the payload (Python for a PyPI incident, Node for an npm one),
   and never change or delete files. Cleanup steps go in the README for a
   person to run.
2. No network. No curl, no DNS lookups, no telemetry. Talking to a local
   daemon (for example `docker images`) is fine if it is skipped quietly when
   the daemon is not there.
3. POSIX `sh` only. No bash arrays, no `[[ ]]`, no `local`. Use tools that
   exist on both Linux and macOS, and fall back when they differ (`md5sum` or
   `md5`, `sha256sum` or `shasum -a 256`, GNU `stat -c` or BSD `stat -f`).
4. Never print a secret. If a check looks at keys or tokens, print a masked
   prefix at most.
5. Exit 0 when nothing is found, 1 when something is flagged, 2 on a usage
   error. Flagged lines start with `FLAG:`. The last line starts with
   `RESULT:`.
6. Every indicator has a comment with its source. Facts come from primary
   sources: the vendor's advisory, the GHSA, or the project's own blog.
   Researcher findings are fine when the README says whose finding it is.
7. Tests use harmless fixtures. Name fixture files with a `.fixture` suffix
   so running a check over a home folder does not flag this repository.
8. Any example output in a README comes from a real run.

## Template for a new incident

Copy `templates/check` to a new folder named `YYYY-MM-short-name`:

```sh
cp -r templates/check 2026-11-example-incident
```

It contains:

```
YYYY-MM-short-name/
  check.sh            the check (POSIX sh)
  test.sh             tests, sourced helpers in tests/lib.sh
  README.md           what happened, what it checks, how to run, limits, what to do
  fixtures/
    README.md         what each fixture is and why it is safe
    *.fixture         fixture files, copied into a temp folder by test.sh
```

The README has these sections, in this order:

1. Title and a link to the matching article.
2. What happened: three to five sentences, every fact linked to its source.
3. What the script checks.
4. How to run it, with real output.
5. Limits: what a clean result does not prove.
6. If it flags something: numbered steps, most urgent first.
7. Sources.

Then add a row to the table in the top-level README.

## Before you open a pull request

```sh
make lint
make test
```

Both must pass. Please also run the new check on a real machine and paste the
output into its README.
