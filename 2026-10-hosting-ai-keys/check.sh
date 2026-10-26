#!/bin/sh
# breach-checks: 2026-10-hosting-ai-keys
#
# Local inventory of API keys and secrets in env files and shell configs, so you
# know what to rotate after the October 2026 Zeabur, OpenCode and Railway
# incidents. It prints the variable name, a provider guess and a masked prefix.
# It never prints a full value, and it never sends anything anywhere.
#
# Usage: sh check.sh [--env] [-] [file-or-folder ...]
#   With no paths it scans the current folder (env files only, recursively)
#   and your shell startup files. --env also lists the current environment.
#   A single - reads NAME=value lines from standard input.
#
# Exit codes: 0 nothing found, 1 secrets listed, 2 usage error.

set -u

scan_env=0
scan_stdin=0
paths=""
nl='
'
for a in "$@"; do
  case "$a" in
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --env) scan_env=1 ;;
    -) scan_stdin=1 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) paths="$paths$a$nl" ;;
  esac
done

if [ -z "$paths" ] && [ "$scan_stdin" -eq 0 ]; then
  paths=".$nl"
  for f in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" \
           "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.envrc" "$HOME/.env"; do
    [ -f "$f" ] && paths="$paths$f$nl"
  done
fi

# The awk program reads NAME=value, export NAME=value, NAME: value and
# "name": "value" lines. Provider rules follow keyinv.awk from the article.
# Output: <where><TAB><name><TAB><provider><TAB><masked>
# The single quotes are on purpose: this is awk code, not shell.
# shellcheck disable=SC2016
INVENTORY_AWK='
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function unquote(s) {
  s = trim(s)
  if (s ~ /^".*"[,]?$/) { sub(/,$/, "", s); s = substr(s, 2, length(s) - 2) }
  else if (substr(s, 1, 1) == q && substr(s, length(s), 1) == q && length(s) >= 2) { s = substr(s, 2, length(s) - 2) }
  else { sub(/[ \t]+#.*$/, "", s) }
  return s
}
function provider(n, v,   p) {
  p = ""
  if (v ~ /^sk-ant-/) p = "Anthropic"
  else if (v ~ /^sk-or-/) p = "OpenRouter"
  else if (v ~ /^sk-/) p = "OpenAI (probably)"
  else if (v ~ /^AIza/) p = "Google"
  else if (v ~ /^(ghp_|github_pat_)/) p = "GitHub"
  else if (v ~ /^(sk|rk)_live_/) p = "Stripe"
  else if (v ~ /^AKIA/) p = "AWS"
  else if (v ~ /^postgres(ql)?:\/\//) p = "Postgres URL"
  else if (toupper(n) ~ /KEY|TOKEN|SECRET|PASS/) p = "check by hand"
  return p
}
function mask(v,   pre, n) {
  n = length(v)
  if (v ~ /^postgres(ql)?:\/\//) { pre = v; sub(/:\/\/.*/, "://", pre) }
  else if (match(v, /^(sk-ant-|sk-or-|sk-proj-|sk-|AIza|ghp_|github_pat_|sk_live_|rk_live_|AKIA)/)) pre = substr(v, 1, RLENGTH)
  else if (n >= 16) pre = substr(v, 1, 2)
  else pre = ""
  return pre "... (" n " chars)"
}
{
  line = $0
  sub(/\r$/, "", line)
  if (line ~ /^[ \t]*(#|\/\/|$)/) next
  sub(/^[ \t]*-[ \t]+/, "", line)
  name = ""; val = ""
  if (match(line, /^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_.]*[ \t]*=/)) {
    name = substr(line, 1, RLENGTH - 1); val = substr(line, RLENGTH + 1)
    sub(/^[ \t]*export[ \t]+/, "", name)
  } else if (match(line, /^[ \t]*-?[ \t]*"?[A-Za-z_][A-Za-z0-9_.-]*"?[ \t]*:[ \t]/)) {
    name = substr(line, 1, RLENGTH); val = substr(line, RLENGTH + 1)
    sub(/:[ \t]*$/, "", name); sub(/^[ \t]*-?[ \t]*/, "", name); gsub(/"/, "", name)
  } else next
  name = trim(name); val = unquote(val)
  if (val == "" || val ~ /^\$\{?[A-Za-z_]/) next
  p = provider(name, val)
  if (p == "") next
  loc = (where == "environment") ? where : where ":" FNR
  printf "%s\t%s\t%s\t%s\n", loc, name, p, mask(val)
}'

out=$(mktemp "${TMPDIR:-/tmp}/bc-keys.XXXXXX") || exit 2
trap 'rm -f "$out"' EXIT

scan_file() {
  awk -v where="$1" -v q="'" "$INVENTORY_AWK" "$1" >> "$out" 2>/dev/null
}

# Read standard input first, before anything else can consume it.
if [ "$scan_stdin" -eq 1 ]; then
  awk -v where="stdin" -v q="'" "$INVENTORY_AWK" >> "$out"
fi

printf '%s' "$paths" | while IFS= read -r p; do
  [ -n "$p" ] || continue
  if [ -d "$p" ]; then
    find "$p" \( -name .git -o -name node_modules -o -name .venv -o -name venv \) -prune -o -type f \
      \( -name '.env' -o -name '.env.*' -o -name '*.env' -o -name '.envrc' -o -name '.dev.vars' \
         -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' \) \
      -print 2>/dev/null | sort | while IFS= read -r f; do scan_file "$f"; done
  elif [ -f "$p" ]; then
    scan_file "$p"
  else
    echo "skipped (not found): $p" >&2
  fi
done

if [ "$scan_env" -eq 1 ]; then
  env | awk -v where="environment" -v q="'" "$INVENTORY_AWK" >> "$out"
fi

count=$(wc -l < "$out" | tr -d ' ')
if [ "$count" -eq 0 ]; then
  echo "No keys or secrets found in the scanned files."
  echo "RESULT: nothing found."
  exit 0
fi

awk -F '\t' '
  BEGIN { printf "%-40s %-28s %-20s %s\n", "WHERE", "NAME", "PROVIDER (guess)", "MASKED" }
  { printf "%-40s %-28s %-20s %s\n", $1, $2, $3, $4 }' "$out"
echo
echo "RESULT: $count secret(s) listed. Values are masked. Rotate at the provider first, then update the variable and redeploy."
exit 1
