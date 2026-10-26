#!/bin/sh
# Tests for check.sh. Run from anywhere: sh test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
. "$here/../tests/lib.sh"
fx="$here/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/proj/services/api" "$work/proj/node_modules/pkg" "$work/clean"
cp "$fx/app.env.fixture" "$work/proj/.env"
cp "$fx/docker-compose.yml.fixture" "$work/proj/services/api/docker-compose.yml"
cp "$fx/app.env.fixture" "$work/proj/node_modules/pkg/.env"
cp "$fx/settings.json.fixture" "$work/settings.json"
cp "$fx/clean.env.fixture" "$work/clean/.env"

run_check "bad option" sh "$here/check.sh" --bogus
expect_code 2

run_check "project folder" sh "$here/check.sh" "$work/proj"
expect_code 1
expect_out "ANTHROPIC_API_KEY .*Anthropic .*sk-ant-\.\.\. (38 chars)"
expect_out "OPENAI_API_KEY .*OpenAI (probably) .*sk-proj-\.\.\."
expect_out "OPENROUTER_API_KEY .*OpenRouter"
expect_out "GEMINI_API_KEY .*Google .*AIza\.\.\."
expect_out "GITHUB_TOKEN .*GitHub"
expect_out "STRIPE_SECRET_KEY .*Stripe"
expect_out "AWS_ACCESS_KEY_ID .*AWS"
expect_out "DATABASE_URL .*Postgres URL .*postgres://\.\.\."
expect_out "SESSION_SECRET .*check by hand"
expect_out "XAI_TOKEN .*check by hand"
expect_out "REPLICATE_API_TOKEN .*check by hand"
expect_out "RESULT: 11 secret(s) listed"
expect_no_out "NODE_ENV"
expect_no_out "FROM_OTHER_VAR"
expect_no_out "node_modules"
# The most important test: no value is ever printed in full or in part past the prefix.
expect_no_out "FAKEFIXTURE"

run_check "single json file" sh "$here/check.sh" "$work/settings.json"
expect_code 1
expect_out "apiKey .*Anthropic"
expect_no_out "FAKEFIXTURE"

run_check "clean folder" sh "$here/check.sh" "$work/clean"
expect_code 0
expect_out "nothing found"

run_check "environment" env -i PATH="$PATH" HOME="$work/clean" MY_API_TOKEN="FAKEFIXTUREVALUE-env-0009" sh "$here/check.sh" --env "$work/clean"
expect_code 1
expect_out "^environment  *MY_API_TOKEN  *check by hand"
expect_no_out "FAKEFIXTURE"

run_check "stdin" sh -c "printf 'OPENAI_API_KEY=sk-FAKEFIXTUREVALUE-stdin-0010\\nPATH=/usr/bin\\n' | sh '$here/check.sh' -"
expect_code 1
expect_out "^stdin:1  *OPENAI_API_KEY  *OpenAI (probably)  *sk-\\.\\.\\. (30 chars)"
expect_no_out "FAKEFIXTURE"
expect_no_out "PATH"

# Default run with no paths scans the current folder and shell startup files.
cp "$fx/app.env.fixture" "$work/clean/.zshrc"
run_check "defaults" sh -c "cd '$work/proj' && HOME='$work/clean' sh '$here/check.sh'"
expect_code 1
expect_out "\./\.env:2"
expect_out "\.zshrc:2"

finish
