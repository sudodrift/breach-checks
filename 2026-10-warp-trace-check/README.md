# Warp agent traces (October 2026)

Article: [Warp lost some agent traces. Here is how I would find the keys that were in mine.](https://sudodrift.github.io/posts/warp-agent-traces/)

## What happened

On October 23, 2026, Warp noticed someone exploiting a vendor in its infrastructure. Its CEO said on October 26 that the attacker reached "a limited amount of agent trace and telemetry data" for up to about 1% of users ([statement](https://www.linkedin.com/posts/zachlloyd_on-friday-we-became-aware-of-what-we-believe-activity-7520566943272140802-0B7N)). Warp has not said which fields were in those traces, so prompts, command output or keys may have been in them.

## What the script checks

You cannot see Warp's server copy. You can see the copy on your own disk, which holds a lot of the same text. The script:

- copies Warp's `warp.sqlite` (plus `-wal` and `-shm`) to a private temp folder and reads only the copy, then deletes it
- scans your saved prompts (`ai_queries`), saved agent conversations (`agent_tasks`, `agent_conversations`), session restore blocks (`blocks`) and MCP template values (`mcp_server_installations`)
- scans `~/.warp/.mcp.json`
- reads the `[privacy]` and `[agents]` keys in `settings.toml` and says when a documented default is in effect
- prints the kind of secret, a short prefix, the length and where it was found. It never prints a value.

This one is Python, not `sh`, because it needs to read SQLite. It uses only the standard library (Python 3.11 or newer reads `settings.toml`; older versions skip that part). It makes no network calls and writes nothing outside its temp folder.

## How to run it

```sh
python3 warp-trace-check.py
```

Exit code 0 means nothing found, 1 means secrets were listed.

Real output on a demo home folder with fake values only:

```
== Warp local history
  db: ~/.local/state/warp-terminal/warp.sqlite
  prompts: 1  (2026-10-20 10:00:00 .. 2026-10-20 10:00:00 as stored)
  blocks: 1  (2026-10-21 09:00:00 .. 2026-10-21 09:00:00 as stored)
  read: ~/.warp/.mcp.json
== Settings
  file: none found, documented defaults apply
  privacy.telemetry_enabled = true (default)   <- consider changing
  privacy.crash_reporting_enabled = true (default)   <- consider changing
  privacy.secret_redaction.enabled = false (default)   <- consider changing
  agents.cloud_conversation_storage_enabled = true (default)
== Secrets seen locally (values never shown)
  FLAG aws-access-key  AKIA... (20 chars)  in blocks.stylized_output  last seen 2026-10-21 09:00:00
  FLAG github-token    ghp_... (40 chars)  in ai_queries.input  last seen 2026-10-20 10:00:00
  FLAG named-secret    fa... (16 chars)  in ~/.warp/.mcp.json
RESULT: 3 distinct secret(s). Rotate each at the issuer, then check its usage logs.
```

## What a clean result does not prove

- It sees only this machine. Warp's server copy, deleted conversations and older session blocks are out of reach. Clean means "nothing found locally", not "nothing leaked".
- It matches known key shapes, `NAME_TOKEN=value` style lines and JSON style `"NAME_TOKEN": "value"` pairs. Keys with no fixed shape, like a password inside a connection string, can slip past.
- It scans protobuf blobs as bytes and does not decode them.
- Older Warp versions may use other tables. The script skips tables it cannot find.

## If it flags something

Rotate the key at the service that issued it, not in Warp. Deleting the local database does nothing to a copy that already left. Then read that key's usage or audit logs from October 1 onward. The article has the steps for GitHub, AWS, OpenAI, Anthropic and MCP tokens.

## Tests

```sh
sh test.sh
```

The test builds a throwaway SQLite database with made up keys, checks that they are flagged and never printed in full, and checks that an empty home folder comes back clean.
