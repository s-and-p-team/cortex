#!/usr/bin/env bash
# setup-keycloak.sh — the demo's Keycloak setup, once per cluster.
#
# One public client, `lineage-demo`, with the password grant enabled, so that
# token.sh can mint a user's token from a terminal (the platform UI's own
# client refuses that grant, correctly, as a browser SPA). The client carries
# the `basic` scope explicitly: the token the demo mints must name a user, and
# that is stated on the client rather than left to the realm's defaults.
# Nothing else is created — no users, no roles, no other client.
#
# STOPGAP — rossoctl/rossoctl#2446, a realm that cannot name a user. Since
# Keycloak 25 the `sub` claim rides on the `basic` client scope, and the
# rossoctl realm import predating the fix for #2446 has no such scope: every
# token the realm mints, the UI's included, has no `sub`, and the lineage
# plugin — which emits lineage.principal.sub from exactly that claim and
# guesses nothing — sees no user. When the realm lacks the scope as a default,
# this script stops and prints the realm-wide change it would make — a demo
# script does not alter the platform's realm unasked. With APPLY_STOPGAP_2446=1
# it applies the chart's fix to the live realm: the scope (its one mapper,
# oidc-sub-mapper) as a realm default, attached as well to the clients in
# STOPGAP_CLIENTS that already exist, since a default reaches only clients
# created afterwards. On a realm installed with the fix it finds the scope and
# does nothing. Delete realm_sub_scope_stopgap when every supported chart
# carries the fix.
#
# Admin credentials: the platform's `keycloak-initial-admin` Secret (kind
# admin). Idempotent: a write answers 201 (created), 204 (added) or 409
# (already there), and each is the state wanted. Exit 3 = the stopgap is
# needed and was not authorised; nothing was written.
#
# Usage: [APPLY_STOPGAP_2446=1] ./setup-keycloak.sh
#   KC_URL              default http://keycloak.localtest.me:8080 (reachable from the host)
#   REALM               default rossoctl
#   KC_ADMIN_NAMESPACE  default keycloak — where the keycloak-initial-admin Secret lives
#   APPLY_STOPGAP_2446  1 = allowed to make the realm-wide change described above
#   STOPGAP_CLIENTS     default "rossoctl" (the UI's client) — pre-existing clients
#                       the stopgap attaches the scope to, when it runs
set -euo pipefail
KC_URL="${KC_URL:-http://keycloak.localtest.me:8080}"
REALM="${REALM:-rossoctl}"
KC_ADMIN_NAMESPACE="${KC_ADMIN_NAMESPACE:-keycloak}"
APPLY_STOPGAP_2446="${APPLY_STOPGAP_2446:-0}"
STOPGAP_CLIENTS="${STOPGAP_CLIENTS:-rossoctl}"

admin_token() {
  local user pass
  user="$(kubectl -n "$KC_ADMIN_NAMESPACE" get secret keycloak-initial-admin -o jsonpath='{.data.username}' | base64 -d)"
  pass="$(kubectl -n "$KC_ADMIN_NAMESPACE" get secret keycloak-initial-admin -o jsonpath='{.data.password}' | base64 -d)"
  # The password travels on stdin (@-), not the command line, and URL-encoded.
  printf '%s' "$pass" | curl -sS --fail --data-urlencode "grant_type=password" --data-urlencode "client_id=admin-cli" \
    --data-urlencode "username=${user}" --data-urlencode "password@-" \
    "${KC_URL}/realms/master/protocol/openid-connect/token" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

api() {  # $1 = method, $2 = path under /admin/realms/REALM, $3 = JSON body (optional); the HTTP code on stdout
  curl -sS -o /dev/null -w '%{http_code}' -X "$1" -H "Authorization: Bearer ${T}" \
    -H 'content-type: application/json' ${3+-d "$3"} "${KC_URL}/admin/realms/${REALM}$2"
}

get() {  # $1 = path; the JSON body on stdout
  curl -sS --fail -H "Authorization: Bearer ${T}" "${KC_URL}/admin/realms/${REALM}$1"
}

id_of_scope() { get "/client-scopes" | python3 -c 'import json, sys
print(next((s["id"] for s in json.load(sys.stdin) if s["name"] == sys.argv[1]), ""))' "$1"; }
id_of_client() { get "/clients?clientId=$1" | python3 -c 'import json, sys
r = json.load(sys.stdin); print(r[0]["id"] if r else "")'; }
is_realm_default_scope() { get "/default-default-client-scopes" | python3 -c 'import json, sys
sys.exit(0 if any(s["name"] == sys.argv[1] for s in json.load(sys.stdin)) else 1)' "$1"; }

want() {  # $1 = HTTP code, $2 = the codes that mean "done" (space-separated), $3 = what was attempted
  local c
  for c in $2; do [ "$1" = "$c" ] && return 0; done
  echo "error: $3: HTTP $1" >&2; exit 1
}

realm_sub_scope_stopgap() {
  # rossoctl#2446 — see the header. Nothing to do on a realm that has the fix.
  if is_realm_default_scope basic; then
    echo "realm ${REALM}: client scope basic is a realm default — stopgap for rossoctl#2446 not needed"
    return 0
  fi
  echo "realm ${REALM}: no basic client scope among the realm defaults — tokens carry no sub (rossoctl#2446)"
  if [ "$APPLY_STOPGAP_2446" != 1 ]; then
    echo "  stopgap for rossoctl#2446 NOT applied — it would, realm-wide: create client scope basic (sub mapper)," >&2
    echo "  make it a realm default, and attach it to these existing clients: ${STOPGAP_CLIENTS}." >&2
    echo "  Re-run with APPLY_STOPGAP_2446=1 to make that change. Nothing was written." >&2
    exit 3
  fi
  local sid
  sid="$(id_of_scope basic)"
  if [ -z "$sid" ]; then
    want "$(api POST /client-scopes '{"name":"basic","protocol":"openid-connect",
      "description":"OpenID Connect built-in scope: the sub claim (rossoctl#2446 stopgap)",
      "attributes":{"include.in.token.scope":"false","display.on.consent.screen":"false"},
      "protocolMappers":[{"name":"sub","protocol":"openid-connect","protocolMapper":"oidc-sub-mapper",
        "consentRequired":false,"config":{"access.token.claim":"true","introspection.token.claim":"true","lightweight.claim":"false"}}]}')" \
      201 "creating client scope basic"
    sid="$(id_of_scope basic)"
    echo "  stopgap: client scope basic created (sub mapper)"
  fi
  want "$(api PUT "/default-default-client-scopes/${sid}")" "204 409" "making basic a realm default scope"
  echo "  stopgap: client scope basic is now a realm default (clients created from here on carry sub)"
  local c cid
  for c in $STOPGAP_CLIENTS; do
    cid="$(id_of_client "$c")"
    if [ -z "$cid" ]; then
      echo "  stopgap: client $c absent — nothing to attach (created later, it inherits the default)"
      continue
    fi
    want "$(api PUT "/clients/${cid}/default-client-scopes/${sid}")" "204 409" "attaching basic to client $c"
    echo "  stopgap: client $c: basic scope attached"
  done
}

demo_client() {
  local cid
  cid="$(id_of_client lineage-demo)"
  if [ -z "$cid" ]; then
    want "$(api POST /clients '{"clientId":"lineage-demo","name":"lineage-demo",
      "description":"lineage demo: mints a user token from the command line (token.sh)",
      "enabled":true,"publicClient":true,"protocol":"openid-connect",
      "standardFlowEnabled":false,"implicitFlowEnabled":false,"directAccessGrantsEnabled":true,
      "serviceAccountsEnabled":false,"fullScopeAllowed":true}')" \
      201 "creating client lineage-demo"
    cid="$(id_of_client lineage-demo)"
    echo "client lineage-demo: created (public, password grant)"
  else
    echo "client lineage-demo: present"
  fi
  # Stated on the client, whatever the realm's defaults are or were.
  want "$(api PUT "/clients/${cid}/default-client-scopes/$(id_of_scope basic)")" "204 409" "attaching basic to client lineage-demo"
  echo "client lineage-demo: basic scope attached (its tokens name the user)"
}

T="$(admin_token)"
realm_sub_scope_stopgap
demo_client
