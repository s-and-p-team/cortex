#!/usr/bin/env bash
# token.sh — a user's access token from the platform's Keycloak, on stdout.
#
# The OAuth password grant against the public `lineage-demo` client that
# setup-keycloak.sh created. Stdout is the raw token and nothing else, so it
# composes: TOKEN=$(./token.sh dev-user dev-user) ./ask.sh "..."
# Stderr says who the token names — its `sub` (the value the lineage plugin
# emits as lineage.principal.sub) and `preferred_username` — so a missing
# `sub` is seen here, not three steps later as an anonymous caller; and its
# `iss` and `aud`, the two values the sidecar's gate matches (AUTH_ISSUER bit
# for bit; AUTH_AUDIENCE any-of), so a generic 401 can be compared against
# what the token actually carries.
#
# Usage: ./token.sh <username> <password>
#   KC_URL  default http://keycloak.localtest.me:8080
#   REALM   default rossoctl
#   CLIENT  default lineage-demo
set -euo pipefail
KC_URL="${KC_URL:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
CLIENT="${CLIENT:-lineage-demo}"
[ $# -eq 2 ] || { echo "usage: $0 <username> <password>" >&2; exit 2; }

curl -sS --data-urlencode "grant_type=password" --data-urlencode "client_id=${CLIENT}" \
  --data-urlencode "username=$1" --data-urlencode "password=$2" --data-urlencode "scope=openid" \
  "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  | python3 -c '
import base64, json, sys
r = json.load(sys.stdin)
tok = r.get("access_token")
if not tok:
    sys.exit("no token: " + json.dumps(r))
body = tok.split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
sub = claims.get("sub") or "ABSENT — the realm mints no sub; run setup-keycloak.sh"
aud = claims.get("aud", [])
aud = [aud] if isinstance(aud, str) else aud
print("user: %s  sub: %s" % (claims.get("preferred_username", "?"), sub), file=sys.stderr)
print("iss: %s  aud: %s" % (claims.get("iss"), " ".join(a for a in aud if not a.startswith("spiffe://")) or "(none)"), file=sys.stderr)
print(tok)'
