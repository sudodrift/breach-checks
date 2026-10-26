# usage: <something that prints NAME=value lines> | awk -F= -f keyinv.awk
$2 ~ /^sk-ant-/                  { p = "Anthropic" }
$2 ~ /^sk-or-/        && !p      { p = "OpenRouter" }
$2 ~ /^sk-/           && !p      { p = "OpenAI (probably)" }
$2 ~ /^AIza/                     { p = "Google" }
$2 ~ /^(ghp_|github_pat_)/       { p = "GitHub" }
$2 ~ /^(sk|rk)_live_/            { p = "Stripe" }
$2 ~ /^AKIA/                     { p = "AWS" }
$2 ~ /^postgres(ql)?:\/\//       { p = "Postgres URL" }
!p && $1 ~ /KEY|TOKEN|SECRET|PASS/ { p = "check by hand" }
p { printf "%-22s %s\n", $1, p; p = "" }
