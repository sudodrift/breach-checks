#!/usr/bin/env python3
"""warp-trace-check: list secrets that sit in Warp's local agent and block history.

Read only. Copies Warp's SQLite database to a private temp folder and reads the
copy, so the live file is never opened for writing. Never prints a secret value:
you get the kind, a short prefix, the length and where it was found.

What it reads (table names from the AGPL Warp client, crates/persistence):
  ai_queries.input            prompts you typed to the agent
  agent_tasks.task            saved agent conversations (protobuf, scanned as bytes)
  blocks.stylized_command/output  commands and output kept for session restore
  mcp_server_installations.variable_values  values you filled into MCP templates
plus ~/.warp/.mcp.json and the [privacy] / [agents] keys in settings.toml.

What it cannot see: Warp's server copy of your traces, conversations you
deleted, or blocks from sessions older than the last restore snapshot. Treat a
clean result as "nothing found locally", not "nothing leaked".
"""
import hashlib, hmac, json, os, re, shutil, sqlite3, sys, tempfile

HOME = os.path.expanduser("~")
XS = os.environ.get("XDG_STATE_HOME") or os.path.join(HOME, ".local/state")
XC = os.environ.get("XDG_CONFIG_HOME") or os.path.join(HOME, ".config")
MAC = os.path.join(HOME, "Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support")
DBS = [os.path.join(XS, "warp-terminal/warp.sqlite"),
       os.path.join(XS, "warp-terminal-preview/warp.sqlite"),
       os.path.join(MAC, "dev.warp.Warp-Stable/warp.sqlite"),
       os.path.join(MAC, "dev.warp.Warp-Preview/warp.sqlite")]
SETTINGS = [os.path.join(XC, "warp-terminal/settings.toml"),
            os.path.join(HOME, ".warp/settings.toml")]

# Shapes mostly from Warp's own recommended redaction list, plus a few common ones.
PATTERNS = [
    ("github-token",   rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b"),
    ("github-fg-pat",  rb"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("aws-access-key", rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("google-api-key", rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("anthropic-key",  rb"\bsk-ant-(?:api|admin)\d{0,2}-[A-Za-z0-9_\-]{80,120}"),
    ("openai-key",     rb"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{40,200}"),
    ("stripe-key",     rb"\b[rs]k_(?:test|live)_[0-9A-Za-z]{24,}\b"),
    ("slack-token",    rb"\bxox[abposr]-[0-9A-Za-z\-]{10,}"),
    ("npm-token",      rb"\bnpm_[A-Za-z0-9]{36}\b"),
    ("jwt",            rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("private-key",    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("named-secret",   rb"(?i)\b[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*\s*[=:]\s*['\"]?([^\s'\"\\]{8,})"),
]
RX = [(n, re.compile(p)) for n, p in PATTERNS]
SALT = os.urandom(32)  # per run, only used to spot the same value twice

def mask(v):
    v = v.decode("utf-8", "replace")
    m = re.match(r"(sk-ant-api\d\d-|sk-proj-|sk-|ghp_|gho_|ghs_|github_pat_|AKIA|ASIA|AIza|xox.-|npm_|[rs]k_live_|[rs]k_test_|eyJ|-----BEGIN)", v)
    pre = m.group(1) if m else v[:2]
    return pre, len(v), hmac.new(SALT, v.encode(), hashlib.sha256).hexdigest()[:12]

def scan_bytes(buf):
    for name, rx in RX:
        for m in rx.finditer(buf):
            yield name, (m.group(1) if m.groups() else m.group(0))

def copy_db(path, tmp):
    dst = os.path.join(tmp, "warp.sqlite")
    for suf in ("", "-wal", "-shm"):
        if os.path.exists(path + suf):
            shutil.copy2(path + suf, dst + suf)
    return dst

def cols(con, table):
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})")]

def scan_db(path, found):
    tmp = tempfile.mkdtemp(prefix="warpcheck-"); os.chmod(tmp, 0o700)
    try:
        con = sqlite3.connect(copy_db(path, tmp))
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        jobs = [("ai_queries", "input", "start_ts"),
                ("agent_tasks", "task", "last_modified_at"),
                ("agent_conversations", "conversation_data", "last_modified_at"),
                ("blocks", "stylized_command", "start_ts"),
                ("blocks", "stylized_output", "start_ts"),
                ("mcp_server_installations", "variable_values", "last_modified_at")]
        info = {}
        if "ai_queries" in tables:
            info["prompts"] = con.execute("SELECT count(*), min(start_ts), max(start_ts) FROM ai_queries").fetchone()
        if "agent_conversations" in tables:
            info["conversations"] = con.execute("SELECT count(*), min(last_modified_at), max(last_modified_at) FROM agent_conversations").fetchone()
        if "blocks" in tables:
            info["blocks"] = con.execute("SELECT count(*), min(start_ts), max(start_ts) FROM blocks").fetchone()
        for t, c, ts in jobs:
            if t not in tables or c not in cols(con, t):
                continue
            tscol = ts if ts in cols(con, t) else "NULL"
            for val, when in con.execute(f"SELECT {c}, {tscol} FROM {t}"):
                if val is None:
                    continue
                buf = val if isinstance(val, bytes) else str(val).encode()
                for kind, v in scan_bytes(buf):
                    pre, ln, fp = mask(v)
                    f = found.setdefault(fp, {"kind": kind, "prefix": pre, "len": ln, "where": set(), "last": ""})
                    f["where"].add(f"{t}.{c}")
                    if when and str(when) > f["last"]:
                        f["last"] = str(when)
        con.close()
        return info
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def scan_file(path, label, found):
    try:
        buf = open(path, "rb").read()
    except OSError:
        return False
    for kind, v in scan_bytes(buf):
        pre, ln, fp = mask(v)
        f = found.setdefault(fp, {"kind": kind, "prefix": pre, "len": ln, "where": set(), "last": ""})
        f["where"].add(label)
    return True

def settings_report():
    try:
        import tomllib
    except ImportError:
        return ["  (python 3.11+ needed to read settings.toml; check Settings > Privacy by hand)"]
    path = next((p for p in SETTINGS if os.path.exists(p)), None)
    data = {}
    if path:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    pv = data.get("privacy", {}); ag = data.get("agents", {})
    rows = [("privacy.telemetry_enabled", pv.get("telemetry_enabled"), True, False),
            ("privacy.crash_reporting_enabled", pv.get("crash_reporting_enabled"), True, False),
            ("privacy.secret_redaction.enabled", pv.get("secret_redaction", {}).get("enabled"), False, True),
            ("agents.cloud_conversation_storage_enabled", ag.get("cloud_conversation_storage_enabled"), True, None)]
    out = [f"  file: {path.replace(HOME, '~') if path else 'none found, documented defaults apply'}"]
    for key, val, default, want in rows:
        eff = default if val is None else val
        src = "default" if val is None else "set"
        flag = "" if want is None or eff == want else "   <- consider changing"
        out.append(f"  {key} = {str(eff).lower()} ({src}){flag}")
    return out

def main():
    found = {}
    dbs = [p for p in DBS if os.path.exists(p)]
    print("== Warp local history")
    if not dbs:
        print("  no warp.sqlite found in the usual places")
    for p in dbs:
        print(f"  db: {p.replace(HOME, '~')}")
        info = scan_db(p, found)
        for k, (n, a, b) in info.items():
            print(f"  {k}: {n}" + (f"  ({a} .. {b} as stored)" if n else ""))
    if scan_file(os.path.join(HOME, ".warp/.mcp.json"), "~/.warp/.mcp.json", found):
        print("  read: ~/.warp/.mcp.json")
    print("== Settings")
    for l in settings_report():
        print(l)
    print("== Secrets seen locally (values never shown)")
    if not found:
        print("  ok: no known secret shapes found. That covers the local copy only.")
        return 0
    order = sorted(found.values(), key=lambda f: (f["kind"] == "named-secret", f["kind"]))
    for f in order:
        where = ", ".join(sorted(f["where"]))
        last = f"  last seen {f['last']}" if f["last"] else ""
        print(f"  FLAG {f['kind']:<15} {f['prefix']}... ({f['len']} chars)  in {where}{last}")
    print(f"RESULT: {len(found)} distinct secret(s). Rotate each at the issuer, then check its usage logs.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
