# Fixtures

All values are fake and say FAKEFIXTURE in them. The GitHub, AWS and Stripe
style values are deliberately too short to look like real keys, so secret
scanners will not mistake them for leaks.

Every file ends in `.fixture` so that running `check.sh` in this repository
does not list them. `test.sh` copies them into a temporary folder with real
names (`.env`, `docker-compose.yml`, `settings.json`) before each test.

- `app.env.fixture`: one line per provider rule, plus lines that must not be
  listed (`NODE_ENV`, `PORT`, and a value that only points at another
  variable).
- `docker-compose.yml.fixture`: list style and map style environment entries.
- `settings.json.fixture`: a JSON config with an `apiKey` field.
- `clean.env.fixture`: nothing secret, should give a clean result.
