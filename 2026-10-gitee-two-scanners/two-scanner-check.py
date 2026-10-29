#!/usr/bin/env python3
"""two-scanner-check: run TruffleHog and Kingfisher over one local git repo's
full history, merge the results by secret value, and show which scanner found
what. Values are never printed, only a short prefix, the length and a hash.

Usage:
  python3 two-scanner-check.py /path/to/repo            # validates keys with each provider
  python3 two-scanner-check.py /path/to/repo --no-verify  # pattern match only, no network

Needs `trufflehog` and `kingfisher` on PATH. sudodrift, MIT licence.
"""
import hashlib, json, os, shutil, subprocess, sys

def need(tool):
    if not shutil.which(tool):
        sys.exit(f"missing: {tool} (install it first, see the article)")

def mask(v):
    return f"{v[:6]}... len={len(v)} sha256:{hashlib.sha256(v.encode()).hexdigest()[:10]}"

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout

def trufflehog(repo, verify):
    cmd = ["trufflehog", "git", "file://" + repo, "--json", "--no-update"]
    cmd += ["--results=verified,unknown"] if verify else ["--no-verification"]
    out = []
    for line in run(cmd).splitlines():
        try: r = json.loads(line)
        except ValueError: continue
        g = r.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        status = "LIVE" if r.get("Verified") else ("unknown" if r.get("VerificationError") else ("not checked" if not verify else "dead"))
        out.append(dict(value=r.get("Raw", ""), kind=r.get("DetectorName", "?"),
                        file=g.get("file", "?"), commit=g.get("commit", "")[:7], status=status))
    return out

def kingfisher(repo, verify):
    cmd = ["kingfisher", "scan", repo, "--format", "json", "--git-history", "full", "--no-update-check"]
    if not verify: cmd.append("--no-validate")
    raw = run(cmd).lstrip()
    try: data = json.JSONDecoder().raw_decode(raw)[0] if raw else {}
    except ValueError: sys.exit("could not read kingfisher output; run it by hand to see why")
    out = []
    for f in data.get("findings", []):
        x = f.get("finding", {}); outcome = x.get("validation", {}).get("outcome", "")
        status = {"active": "LIVE", "inactive": "dead", "not_attempted": "not checked"}.get(outcome, outcome or "?")
        out.append(dict(value=x.get("snippet", ""), kind=f.get("rule", {}).get("name", "?"),
                        file=x.get("path", "?"), commit=x.get("git_metadata", {}).get("commit", {}).get("id", "")[:7],
                        status=status))
    return out

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    verify = "--no-verify" not in sys.argv
    if not args: sys.exit(__doc__)
    repo = os.path.abspath(args[0]); need("trufflehog"); need("kingfisher")
    th, kf = trufflehog(repo, verify), kingfisher(repo, verify)
    merged = {}
    for name, rows in (("trufflehog", th), ("kingfisher", kf)):
        for r in rows:
            if not r["value"]: continue
            m = merged.setdefault(r["value"], dict(r, by=set()))
            m["by"].add(name)
            if r["status"] == "LIVE": m["status"] = "LIVE"
    print(f"== repo: {repo}  (validation {'on' if verify else 'off'})")
    for v, m in sorted(merged.items(), key=lambda kv: (kv[1]["status"] != "LIVE", kv[1]["kind"])):
        by = "both" if len(m["by"]) == 2 else next(iter(m["by"])) + " only"
        tag = "FLAG" if m["status"] in ("LIVE", "not checked", "unknown") else "ok  "
        print(f"{tag} {m['kind']:<20} {mask(v):<44} {m['file']}@{m['commit']}  {by}  [{m['status']}]")
    both = sum(1 for m in merged.values() if len(m["by"]) == 2)
    only_th = sum(1 for m in merged.values() if m["by"] == {"trufflehog"})
    only_kf = sum(1 for m in merged.values() if m["by"] == {"kingfisher"})
    print(f"== unique secrets: {len(merged)}  both: {both}  trufflehog only: {only_th}  kingfisher only: {only_kf}")
    gone = [m for m in merged.values() if not os.path.exists(os.path.join(repo, m["file"]))]
    if gone:
        print(f"== {len(gone)} of these sit in files that no longer exist in your working tree. Still in history. Still need revoking.")
    print("== next: revoke each FLAG at the provider that issued it. Deleting it from git does not.")

if __name__ == "__main__":
    main()
