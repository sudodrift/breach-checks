#!/bin/sh
# Tests warp-trace-check.py against a demo home folder with fake keys only.
set -u
cd "$(dirname "$0")" || exit 2
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not found"; exit 0; }
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT
fail=0
mkdir -p "$T/hit/.local/state/warp-terminal" "$T/hit/.warp" "$T/clean"
FAKE_GH="ghp_$(printf 'F%.0s' $(seq 36))"
FAKE_AWS="AKIAFAKEFAKEFAKEFAKE"
python3 - "$T/hit/.local/state/warp-terminal/warp.sqlite" "$FAKE_GH" "$FAKE_AWS" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("CREATE TABLE ai_queries (input TEXT, start_ts TEXT)")
con.execute("CREATE TABLE blocks (stylized_command TEXT, stylized_output TEXT, start_ts TEXT)")
con.execute("INSERT INTO ai_queries VALUES (?, '2026-10-20 10:00:00')", ("why does " + sys.argv[2] + " get a 401",))
con.execute("INSERT INTO blocks VALUES ('env', ?, '2026-10-21 09:00:00')", ("AWS_ACCESS_KEY_ID=" + sys.argv[3],))
con.commit()
PY
printf 'SERVICE_TOKEN=fakefakefakefake\n' > "$T/hit/.warp/.mcp.json"
out=$(HOME="$T/hit" XDG_STATE_HOME= XDG_CONFIG_HOME= python3 warp-trace-check.py); rc=$?
[ "$rc" -eq 1 ] || { echo "FAIL: flagged case exit $rc, want 1"; fail=1; }
echo "$out" | grep -q "FLAG github-token" || { echo "FAIL: github token not found"; fail=1; }
echo "$out" | grep -q "FLAG aws-access-key" || { echo "FAIL: aws key not found"; fail=1; }
for v in "$FAKE_GH" "$FAKE_AWS" fakefakefakefake; do
  case "$out" in *"$v"*) echo "FAIL: a full value was printed"; fail=1 ;; esac
done
HOME="$T/clean" XDG_STATE_HOME= XDG_CONFIG_HOME= python3 warp-trace-check.py >/dev/null; rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: clean case exit $rc, want 0"; fail=1; }
[ "$fail" -eq 0 ] && echo "PASS: warp-trace-check"
exit "$fail"
