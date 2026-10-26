# AI keys taken from hosting platforms (October 2026)

Article: [Someone Spent a Week Raiding Hosting Platforms for AI Keys. Here's How to Check Yours](https://sudodrift.github.io/posts/ai-keys-hosting-platforms/)

## What happened

Zeabur says an attacker used plaintext internal AWS keys and Kubernetes admin tokens on October 14 and 15, 2026, and read 3,218,965 environment variable records (names and values) from its platform database, along with data inside 865 customer database containers ([Zeabur report](https://zeabur.com/blogs/october-2026-security-incident)). OpenCode said on October 17 that a breach the night before affected 1.4% of OpenCode Console users who had external AI providers linked, and that users who did not get its email were not affected ([OpenCode on X](https://x.com/i/status/2111519637049319818)). Railway says that on October 21 an attacker reached its CI environment, picked up more credentials there and decrypted a subset of stored environment variables, at most 1.85% of workspaces, about 100,000 ([Railway preliminary report](https://blog.railway.com/p/preliminary-report-october-security-incident)). Railway and Zeabur both say the attacker was mainly after AI provider keys, and both tell every user to rotate what they stored on the platform ([Railway disclosure](https://blog.railway.com/p/security-disclosure-wednesday-october-21st)).

## What the script checks

It is an inventory, not a compromise detector. It answers "which secrets do I have that might also live on a hosting platform?" so you know what to rotate.

- It reads env style files under a folder (`.env`, `.env.*`, `*.env`, `.envrc`, `.dev.vars`, `docker-compose*.yml`, `compose*.yml`), any file you name directly (JSON or YAML configs work), your shell startup files, and with `--env` the current environment. A single `-` reads `NAME=value` lines from standard input.
- It understands `NAME=value`, `export NAME=value`, `NAME: value`, `- NAME=value` and `"name": "value"` lines.
- It guesses the provider from the value prefix, using the same rules as `keyinv.awk` from the article: Anthropic, OpenRouter, OpenAI, Google, GitHub, Stripe, AWS and Postgres URLs. Anything else whose name contains KEY, TOKEN, SECRET or PASS is listed as "check by hand".
- It prints the location, the name, the guess and a masked prefix with the length. It never prints a full value. For Postgres URLs it shows only the scheme, so passwords inside the URL stay hidden.
- It skips `.git`, `node_modules`, `.venv` and `venv`.

`keyinv.awk` is the original one-file version from the article, kept here for people who want to pipe into it directly. It prints names only.

## How to run it

```sh
sh check.sh                    # current folder plus your shell startup files
sh check.sh ~/code/myapp       # one project
sh check.sh --env              # also list secrets in the current environment
```

For Railway, the article uses `railway run`, which injects one service's variables into a local command. Your own shell variables show up too, so ignore those:

```sh
railway run -s api -e production -- env | sh check.sh -
```

(I did not run the Railway line here. The Railway CLI is not installed on the test box.)

Exit code 0 means nothing found, 1 means secrets were listed, 2 means a usage error.

Real output against a folder made from the test fixtures, which hold fake values only:

```
$ cd /tmp/keysdemo && sh check.sh .
WHERE                                    NAME                         PROVIDER (guess)     MASKED
./.env:2                                 ANTHROPIC_API_KEY            Anthropic            sk-ant-... (38 chars)
./.env:3                                 OPENAI_API_KEY               OpenAI (probably)    sk-proj-... (36 chars)
./.env:4                                 OPENROUTER_API_KEY           OpenRouter           sk-or-... (38 chars)
./.env:5                                 GEMINI_API_KEY               Google               AIza... (32 chars)
./.env:6                                 GITHUB_TOKEN                 GitHub               ghp_... (15 chars)
./.env:7                                 STRIPE_SECRET_KEY            Stripe               sk_live_... (12 chars)
./.env:8                                 AWS_ACCESS_KEY_ID            AWS                  AKIA... (15 chars)
./.env:9                                 DATABASE_URL                 Postgres URL         postgres://... (55 chars)
./.env:10                                SESSION_SECRET               check by hand        FA... (29 chars)
./api/docker-compose.yml:5               XAI_TOKEN                    check by hand        FA... (29 chars)
./api/docker-compose.yml:7               REPLICATE_API_TOKEN          check by hand        FA... (29 chars)

RESULT: 11 secret(s) listed. Values are masked. Rotate at the provider first, then update the variable and redeploy.
```

## Limits

- Prefix guesses are rough. Many keys have no prefix, which is why the "check by hand" rule exists.
- It does not read secret managers, cloud consoles or the hosting platform itself. Use the platform's own variable list for that.
- A quiet usage graph is not proof a key was not used. A database password or token used once leaves no spike.

## If it lists something

1. Revoke the key at the provider first. Changing the variable on the platform does not kill the old key.
2. Create a new key, ideally one per service with a spend limit, update the variable and redeploy. Railway's [Postgres guide](https://blog.railway.com/p/security-disclosure-recommendation-rotate-postgresql-database-credentials) notes that containers read variables only at startup, so a service you do not redeploy keeps the old value.
3. Database passwords: change the password inside the database, not only the variable. Zeabur warns that editing the variable does not change the database password. The same Railway guide says to use Regenerate instead of running ALTER USER by hand.
4. If you ran n8n on Zeabur's shared cluster, replace the n8n encryption key and recreate all credentials in n8n. Zeabur found 602 of the 607 instances it checked kept that key in an environment variable.
5. Check usage at each provider from the earliest date the platform gives: October 14 for Zeabur (September 1 for its GCP dedicated servers), and the dates in each platform's notice for the others.

## Sources

- Zeabur, October 2026 security incident (preliminary report): https://zeabur.com/blogs/october-2026-security-incident
- OpenCode, statement on X, October 17, 2026: https://x.com/i/status/2111519637049319818
- Railway, Security Disclosure: Wednesday October 21st: https://blog.railway.com/p/security-disclosure-wednesday-october-21st
- Railway, Preliminary Report: Oct 21st Security Incident: https://blog.railway.com/p/preliminary-report-october-security-incident
- Railway, Rotate PostgreSQL Database Credentials: https://blog.railway.com/p/security-disclosure-recommendation-rotate-postgresql-database-credentials
