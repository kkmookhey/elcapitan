#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
project="elcapitan-acceptance-$$"
token="local-acceptance-not-a-secret-00000000"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/elcapitan-acceptance.XXXXXX")
cookie="$temporary/cookie.txt"
headers="$temporary/headers.txt"
intake="$temporary/intake.json"
fleet="$temporary/fleet.json"
started=$(date +%s)

cleanup() {
  docker compose --project-directory "$repository" --project-name "$project" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f -- "$cookie" "$headers" "$intake" "$fleet"
  rmdir -- "$temporary" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

export ELCAPITAN_QUICKSTART_ACCESS_TOKEN="$token"

docker compose --project-directory "$repository" --project-name "$project" \
  up --build --detach --wait --wait-timeout 180

health=$(curl --fail --silent --show-error http://127.0.0.1:8770/healthz)
printf '%s' "$health" | grep -q '"status":"ok"'
printf '%s' "$health" | grep -q '"state_store":"postgresql"'

login_status=$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' --cookie-jar "$cookie" --dump-header "$headers" \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$token" http://127.0.0.1:8770/login)
test "$login_status" = "303"
grep -Eiq '^Set-Cookie:.*HttpOnly' "$headers"
grep -Eiq '^Set-Cookie:.*Secure' "$headers"
grep -Eiq '^Set-Cookie:.*SameSite=Strict' "$headers"
grep -Eiq '^Set-Cookie:.*Max-Age=28800' "$headers"

curl --fail --silent --show-error --cookie "$cookie" \
  http://127.0.0.1:8770/ | grep -q 'aria-labelledby="intake-title"'
curl --fail --silent --show-error --cookie "$cookie" \
  http://127.0.0.1:8770/fleet.css | grep -q ':focus-visible'
curl --fail --silent --show-error --cookie "$cookie" \
  http://127.0.0.1:8770/fleet.js | grep -q 'Current approval package'

cross_origin_status=$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' --cookie "$cookie" \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://attacker.invalid' --data '{}' \
  http://127.0.0.1:8770/api/intake)
test "$cross_origin_status" = "403"

execution_status=$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' --cookie "$cookie" \
  --header 'Content-Type: application/json' --data '{}' \
  http://127.0.0.1:8770/api/execute)
test "$execution_status" = "404"

curl --fail --silent --show-error --cookie "$cookie" \
  --header 'Content-Type: application/json' \
  --data-binary "@$repository/examples/synthetic-shadow-intake.json" \
  http://127.0.0.1:8770/api/intake >"$intake"
grep -q '"received":1' "$intake"
grep -q '"created_cases":1' "$intake"

curl --fail --silent --show-error --cookie "$cookie" \
  'http://127.0.0.1:8770/api/fleet?tenant=SYNTHETIC-QUICKSTART' >"$fleet"
grep -q '"total_findings":1' "$fleet"
grep -q '"synthetic":true' "$fleet"
grep -q '"evidence_grade":"e2e_measured"' "$fleet"

elapsed=$(($(date +%s) - started))
if [ "$elapsed" -gt 600 ]; then
  echo "quickstart acceptance exceeded 600 seconds: ${elapsed}s" >&2
  exit 1
fi

echo "quickstart acceptance passed in ${elapsed}s (PostgreSQL, synthetic input, no cloud/model credentials)"
