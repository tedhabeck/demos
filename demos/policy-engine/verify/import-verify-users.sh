#!/usr/bin/env bash
# Provision the demo personas into an IBM Verify tenant from verify/users.csv.
#
# This closes the gap left by decision D5 in
# docs/brainstorms/2026-08-31-ibm-verify-idp-requirements.md ("tenant setup is
# documented, not automated") for the part that is most tedious and most
# error-prone by hand: the four users, their four custom attributes, and the
# array-shape padding those attributes require.
#
# Usage:
#   ./import-verify-users.sh                    # create attrs + users
#   ./import-verify-users.sh --dry-run          # print the SCIM payloads, send nothing
#   ./import-verify-users.sh --attrs-only       # define the custom attributes, no users
#   ./import-verify-users.sh --users-only       # assume attributes already exist
#   ./import-verify-users.sh --csv other.csv    # a different user source
#   ./import-verify-users.sh --delete           # remove the CSV's users from the tenant
#
# Requires: curl, jq, python3 (CSV parsing only — no third-party packages).
#
# ---------------------------------------------------------------------------
# What this needs from the tenant, and why it is a SEPARATE client
# ---------------------------------------------------------------------------
# The Users and Attributes APIs authenticate with a Verify *API client* whose
# entitlements are checked per-endpoint — these are entitlements, not OAuth
# scopes:
#
#   manageUsers       (or manageUserGroups)  -> POST/DELETE /v2.0/Users
#   manageAttributes                         -> POST /v1.0/attributes
#
# Neither hr-copilot (HR_COPILOT_CLIENT_ID) nor the gateway exchange client
# (GATEWAY_CLIENT_ID) has them, and they should not: those two are in the demo's
# hot path, and a client that can mint alice's token should not also be able to
# rewrite alice's permissions. Create a third API client in
#   Security -> API access -> Add API client
# and put its credentials in .env.verify (gitignored) as:
#
#   VERIFY_ADMIN_CLIENT_ID=...
#   VERIFY_ADMIN_CLIENT_SECRET=...
#
# The tenant URL is derived from IBM_VERIFY_TOKEN_ENDPOINT in
# post_deploy_variables.json, so there is nothing else to configure.
#
# ---------------------------------------------------------------------------
# The empty-string padding is load-bearing — do not remove it
# ---------------------------------------------------------------------------
# Verify serialises a custom attribute holding exactly one value as a JSON
# SCALAR, not a one-element array. Praxis's standard claim mapper reads
# roles/teams/permissions via Value::as_array
# (builtins/plugins/identity-jwt/src/claim_map.rs:222,248), which returns None
# for a JSON string — so a single-role persona gets an EMPTY subject.roles with
# no error raised, `require(role.hr)` fails, and the whole thing presents as a
# policy deny rather than the config fault it actually is.
#
# Every multi-valued attribute below is therefore padded with a trailing ""
# so the claim is always array-shaped. The cost, accepted knowingly: "" becomes
# a real set member and will appear in audit records and X-Policy-* debug
# output. Remove the padding only once the upstream scalar->vec fallback lands.
#
# gh_permissions is padded too, for consistency, though it does not strictly
# need it: it is a passthrough claim (subject.claims) rather than one of the
# mapper's structured array fields, so it never reaches as_array.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CSV="$SCRIPT_DIR/users.csv"
DRY_RUN=false
DO_ATTRS=true
DO_USERS=true
DO_DELETE=false

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)    DRY_RUN=true ;;
    --attrs-only) DO_USERS=false ;;
    --users-only) DO_ATTRS=false ;;
    --delete)     DO_DELETE=true; DO_ATTRS=false ;;
    --csv)        CSV="${2:?--csv needs a path}"; shift ;;
    # Print just the synopsis (down to the "Requires:" line), not the whole
    # rationale essay in the header.
    -h|--help)    sed -n '2,/^# Requires:/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

ok()   { printf "  %s %-30s %s\n" "$(green ✓)" "$1" "${2:-}"; }
warn() { printf "  %s %-30s %s\n" "$(yellow !)" "$1" "${2:-}"; }
fail() { printf "  %s %-30s %s\n" "$(red ✗)" "$1" "${2:-}"; }

die() { echo "$(red ERROR:) $*" >&2; exit 1; }

for tool in curl jq python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required but not on PATH"
done
[ -f "$CSV" ] || die "user source not found: $CSV"

# --- tenant + credentials -------------------------------------------------
PDV="$DEMO_DIR/post_deploy_variables.json"
[ -f "$PDV" ] || die "post_deploy_variables.json not found at $PDV"

TOKEN_ENDPOINT=$(jq -r '.variables.IBM_VERIFY_TOKEN_ENDPOINT // empty' "$PDV")
[ -n "$TOKEN_ENDPOINT" ] || die "IBM_VERIFY_TOKEN_ENDPOINT missing from $PDV"

# https://praxis-1.verify.ibm.com/oauth2/token -> https://praxis-1.verify.ibm.com
TENANT_URL="${TOKEN_ENDPOINT%/oauth2/token}"
[ "$TENANT_URL" != "$TOKEN_ENDPOINT" ] \
  || die "could not derive tenant URL from IBM_VERIFY_TOKEN_ENDPOINT ('$TOKEN_ENDPOINT'); expected it to end in /oauth2/token"

# .env.verify is gitignored and holds the admin API client. Prefer an already
# exported value so CI or a one-off run can override without editing the file.
if [ -f "$DEMO_DIR/.env.verify" ]; then
  # shellcheck disable=SC1091
  set -a; . "$DEMO_DIR/.env.verify"; set +a
fi

ADMIN_ID="${VERIFY_ADMIN_CLIENT_ID:-}"
ADMIN_SECRET="${VERIFY_ADMIN_CLIENT_SECRET:-}"

if [ "$DRY_RUN" = false ] && { [ -z "$ADMIN_ID" ] || [ -z "$ADMIN_SECRET" ]; }; then
  cat >&2 <<EOF
$(red 'ERROR:') VERIFY_ADMIN_CLIENT_ID / VERIFY_ADMIN_CLIENT_SECRET are not set.

The Users and Attributes APIs need an API client with the 'manageUsers' and
'manageAttributes' entitlements. This is deliberately NOT hr-copilot and NOT
the gateway exchange client — see the header of this script for why.

  1. Verify admin console -> Security -> API access -> Add API client
  2. Grant: "Manage users and groups" and "Manage attributes"
  3. Add the credentials to $DEMO_DIR/.env.verify:

       VERIFY_ADMIN_CLIENT_ID=<uuid>
       VERIFY_ADMIN_CLIENT_SECRET=<secret>

Re-run with --dry-run to inspect the payloads without any credentials.
EOF
  exit 1
fi

# --- access token ---------------------------------------------------------
ACCESS_TOKEN=""
get_token() {
  local resp
  resp=$(curl -sS -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=$ADMIN_ID" \
    -d "client_secret=$ADMIN_SECRET") || die "token request to $TOKEN_ENDPOINT failed"

  ACCESS_TOKEN=$(printf '%s' "$resp" | jq -r '.access_token // empty')
  if [ -z "$ACCESS_TOKEN" ]; then
    fail "admin token" "$(printf '%s' "$resp" | jq -r '.error_description // .error // "no access_token in response"')"
    printf '%s\n' "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
    die "could not obtain an admin access token"
  fi
  ok "admin token" "$(dim "client ${ADMIN_ID:0:8}…")"
}

# api <METHOD> <PATH> [BODY] -> prints "<body>\n<http_status>"
#
# The two APIs this script talks to do NOT share a media type, and getting it
# wrong is a 406 rather than a helpful error:
#
#   /v2.0/Users      SCIM  -> application/scim+json
#   /v1.0/attributes plain -> application/json
#
# The Attributes API rejects scim+json in Accept with "406 Not Acceptable"
# before it ever looks at the body, so send each endpoint the type it declares.
api() {
  local method="$1" path="$2" body="${3:-}"
  local ctype="application/json"
  case "$path" in
    /v2.0/*) ctype="application/scim+json; charset=utf-8" ;;
  esac
  local -a args=(-sS -o - -w $'\n%{http_code}' -X "$method" "${TENANT_URL}${path}"
    -H "Authorization: Bearer $ACCESS_TOKEN"
    -H "Accept: $ctype")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: $ctype" -d "$body")
  fi
  curl "${args[@]}"
}

# Split "<body>\n<status>" from api() into the globals RESP_BODY / RESP_STATUS.
_split_resp() {
  RESP_STATUS="${1##*$'\n'}"
  RESP_BODY="${1%$'\n'*}"
}

# ==========================================================================
# 1. Custom attribute definitions
# ==========================================================================
# A custom attribute must exist in the TENANT SCHEMA before a user payload may
# carry it — an undefined attribute fails the create with a validation error
# rather than being created implicitly. Each definition claims one of the
# predefined customAttribute1..150 slots.
#
# datatype string[] is what keeps these multi-valued. The slot numbers are
# arbitrary but must be stable: changing one after users exist orphans the
# stored values.
#
# Verify's scimName validator accepts LETTERS ONLY — an underscore or hyphen is
# rejected with "CSIAI0096E The value <x> is not valid for attribute [scimName]"
# (a 400 that is NOT an "already exists" 400). So the display name and the
# scimName have to be allowed to differ: gh_permissions -> ghpermissions.
#
# The scimName is the operative one — the CELx claim mappers call
# user.getCustomValues("<scimName>"), and import-verify-clients.sh resolves it
# from the tenant rather than assuming name == scimName. Keep this in sync with
# that script and with verify/README.md.
#
# Format: displayName:slot:scimName
ATTRS=(
  "roles:customAttribute1:roles"
  "permissions:customAttribute2:permissions"
  "teams:customAttribute3:teams"
  "gh_permissions:customAttribute4:ghpermissions"
)

# --- CSV -> JSON ----------------------------------------------------------
# Parsed with python3's csv module rather than IFS=, read: it handles quoting
# and CRLF correctly, and it lets the '##' comment convention in users.csv work.
# Columns are read BY HEADER NAME, so the CSV stays reorderable and an operator
# can add a column without touching the field offsets here.
#
# Multi-valued cells are pipe-separated (see users.csv), and each list gets the
# trailing "" pad described in the header comment.
csv_json() {
  # Build "csvName=scimName,..." from ATTRS so the two never drift apart.
  local entry map=""
  for entry in "${ATTRS[@]}"; do
    map+="${entry%%:*}=${entry##*:},"
  done
  python3 - "$CSV" "${map%,}" <<'PY'
import csv, json, sys

REQUIRED = ["username", "email", "first_name", "last_name", "password"]

# Custom attributes, in the order they are emitted. The CSV column keeps the
# readable name (gh_permissions); the SCIM payload must use the tenant's
# scimName, which is letters-only (ghpermissions). The map arrives as
# "csvName=scimName,..." in argv[2] so ATTRS in the shell below stays the single
# source of truth for that pairing.
ATTR_MAP = [tuple(pair.split("=", 1)) for pair in sys.argv[2].split(",") if pair]

with open(sys.argv[1], newline="") as fh:
    # '##' lines are documentation, not data. Blank lines are skipped so the
    # file can be visually grouped.
    rows = [ln for ln in fh if not ln.lstrip().startswith("##") and ln.strip()]

reader = csv.DictReader(rows)
missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
if missing:
    sys.exit(f"users.csv is missing required column(s): {', '.join(missing)}\n"
             f"found: {', '.join(reader.fieldnames or [])}")

out = []
seen = set()
for i, row in enumerate(reader, start=2):
    user = {k: (row.get(k) or "").strip() for k in REQUIRED}
    if not user["username"]:
        sys.exit(f"row {i}: empty username")
    if user["username"] in seen:
        sys.exit(f"row {i}: duplicate username {user['username']!r}")
    seen.add(user["username"])
    if not user["password"]:
        # Verify would mail a generated password to an @corp.com address that
        # does not resolve, so ROPC minting would then be impossible.
        sys.exit(f"row {i}: {user['username']} has no password; "
                 f"mint-verify-token.sh needs one to use the password grant")

    attrs = {}
    for name, scim in ATTR_MAP:
        raw = (row.get(name) or "").strip()
        vals = [v.strip() for v in raw.split("|") if v.strip()]
        # THE PAD IS LOAD-BEARING. See the script header: without a second
        # element Verify emits a scalar and Praxis's claim mapper silently
        # drops the claim, which surfaces as a policy deny.
        attrs[scim] = vals + [""]
    user["attributes"] = attrs
    out.append(user)

json.dump(out, sys.stdout)
PY
}

USERS_JSON="$(csv_json)" || die "failed to parse $CSV"
USER_COUNT=$(printf '%s' "$USERS_JSON" | jq 'length')

# Build the SCIM create payload for the user at index $1.
scim_payload() {
  printf '%s' "$USERS_JSON" | jq --argjson i "$1" '
    .[$i] as $u
    | {
        schemas: [
          "urn:ietf:params:scim:schemas:core:2.0:User",
          "urn:ietf:params:scim:schemas:extension:ibm:2.0:User",
          "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification"
        ],
        userName: $u.username,
        name: { givenName: $u.first_name, familyName: $u.last_name },
        # Verify accepts exactly one email and only type "work".
        emails: [ { type: "work", value: $u.email } ],
        active: true,
        password: $u.password,
        "urn:ietf:params:scim:schemas:extension:ibm:2.0:User": {
          userCategory: "regular",
          # NO emailVerified HERE. This tenant rejects it outright:
          #   CSIAI0111E The supplied JSON contained an invalid attribute: emailVerified
          # It is also unnecessary — nothing in the demo exercises an email
          # round-trip, and the Notification block below (notifyType: NONE) is
          # what actually stops Verify mailing the clear-text password to
          # @corp.com, which does not resolve.
          twoFactorAuthentication: false,
          customAttributes: ($u.attributes | to_entries
                              | map({ name: .key, values: .value }))
        },
        # Suppress the account-created email. Without this Verify mails the
        # clear-text password to an address that does not exist.
        "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification": {
          notifyType: "NONE"
        }
      }'
}


attr_payload() {
  local name="$1" slot="$2" scim="$3"
  # attributeName is validated with the same letters-only rule as scimName, so
  # both take $scim. Only the human-facing name/description keep the underscore.
  jq -nc --arg name "$name" --arg slot "$slot" --arg scim "$scim" '{
    name: $name,
    description: ("Policy-engine demo claim: " + $name),
    datatype: "string[]",
    scope: "tenant",
    sourceType: "schema",
    schemaAttribute: {
      name: $slot,
      attributeName: $scim,
      scimName: $scim,
      customAttribute: true
    }
  }'
}

create_attrs() {
  echo
  echo "$(dim 'Custom attribute definitions') $(dim "-> ${TENANT_URL}/v1.0/attributes")"
  local entry name slot scim body rest
  for entry in "${ATTRS[@]}"; do
    name="${entry%%:*}"; rest="${entry#*:}"
    slot="${rest%%:*}"; scim="${rest##*:}"
    body="$(attr_payload "$name" "$slot" "$scim")"

    if [ "$DRY_RUN" = true ]; then
      ok "$name" "$(dim "$slot, scimName=$scim (dry-run)")"
      printf '%s\n' "$body" | jq . | sed 's/^/      /'
      continue
    fi

    _split_resp "$(api POST "/v1.0/attributes" "$body")"
    case "$RESP_STATUS" in
      201|200) ok   "$name" "$(dim "defined as $slot (scimName=$scim)")" ;;
      # Verify returns 400 for an already-defined name as well as for genuine
      # validation errors, so the message is the only way to tell them apart.
      # Treat "exists"/"duplicate" as idempotent success and surface the rest.
      400|409)
        if printf '%s' "$RESP_BODY" | grep -qiE 'exist|duplicate|already|in use'; then
          warn "$name" "$(dim 'already defined — skipped')"
        else
          fail "$name" "HTTP $RESP_STATUS"
          printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
            || printf '      %s\n' "$RESP_BODY"
          # CSIAI0096E on [scimName]/[attributeName] is the letters-only rule,
          # not a transient failure: no retry will help, the ATTRS entry needs a
          # letters-only scimName in its third field.
          if printf '%s' "$RESP_BODY" | grep -qE 'CSIAI0096E|not valid for attribute'; then
            echo "$(dim "      scimName '$scim' was rejected. Verify allows LETTERS ONLY here —")"
            echo "$(dim "      no '_' or '-'. Set a letters-only scimName in the third field of")"
            echo "$(dim "      this attribute's ATTRS entry (e.g. gh_permissions -> ghpermissions).")"
          fi
          die "attribute '$name' could not be defined; users would fail validation"
        fi
        ;;
      403) fail "$name" "HTTP 403 — the API client lacks the 'manageAttributes' entitlement"
           die "insufficient entitlements" ;;
      # /v1.0/attributes is plain JSON, not SCIM. A 406 means something sent it
      # scim+json — see the media-type switch in api().
      406) fail "$name" "HTTP 406 — /v1.0/attributes was sent a non-JSON Accept type"
           die "wrong media type for the Attributes API" ;;
      *)   fail "$name" "HTTP $RESP_STATUS"
           printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
             || printf '      %s\n' "$RESP_BODY"
           die "unexpected response defining '$name'" ;;
    esac
  done
}

# ==========================================================================
# 2. Users
# ==========================================================================
# Look up a userName -> id. Used to make create idempotent and to drive --delete.
find_user_id() {
  local username="$1" filter
  # SCIM filter; the space and quotes must be percent-encoded.
  filter="userName%20eq%20%22${username}%22"
  _split_resp "$(api GET "/v2.0/Users?filter=${filter}")"
  [ "$RESP_STATUS" = "200" ] || return 1
  printf '%s' "$RESP_BODY" | jq -r '.Resources[0].id // empty'
}

create_users() {
  echo
  echo "$(dim 'Users') $(dim "-> ${TENANT_URL}/v2.0/Users")"
  local i username body existing
  for i in $(seq 0 $((USER_COUNT - 1))); do
    username=$(printf '%s' "$USERS_JSON" | jq -r ".[$i].username")
    body="$(scim_payload "$i")"

    if [ "$DRY_RUN" = true ]; then
      ok "$username" "$(dim '(dry-run)')"
      # Redact the password so the payload can be pasted into an issue.
      printf '%s\n' "$body" | jq '.password = "«redacted»"' | sed 's/^/      /'
      continue
    fi

    _split_resp "$(api POST "/v2.0/Users" "$body")"
    case "$RESP_STATUS" in
      201)
        ok "$username" "$(dim "id=$(printf '%s' "$RESP_BODY" | jq -r '.id // "?"')")" ;;
      409)
        # Already present. Overwriting a user's attributes is a bigger action
        # than "import" implies, so report it and let the operator choose
        # --delete then re-run.
        existing=$(find_user_id "$username" || true)
        warn "$username" "$(dim "exists${existing:+ (id=$existing)} — left unchanged; use --delete to replace")" ;;
      400)
        fail "$username" "HTTP 400"
        printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
          || printf '      %s\n' "$RESP_BODY"
        echo "$(dim '      A 400 here is usually an undefined custom attribute:')"
        echo "$(dim '      run with --attrs-only first, or check the slot mapping.')"
        die "user '$username' rejected" ;;
      403)
        fail "$username" "HTTP 403 — the API client lacks the 'manageUsers' entitlement"
        die "insufficient entitlements" ;;
      *)
        fail "$username" "HTTP $RESP_STATUS"
        printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
          || printf '      %s\n' "$RESP_BODY"
        die "unexpected response creating '$username'" ;;
    esac
  done
}

delete_users() {
  echo
  echo "$(yellow 'Deleting') $(dim "the ${USER_COUNT} users in $(basename "$CSV") from ${TENANT_URL}")"
  local i username id
  for i in $(seq 0 $((USER_COUNT - 1))); do
    username=$(printf '%s' "$USERS_JSON" | jq -r ".[$i].username")

    if [ "$DRY_RUN" = true ]; then
      ok "$username" "$(dim '(dry-run) would DELETE /v2.0/Users/<id>')"
      continue
    fi

    if ! id=$(find_user_id "$username") || [ -z "$id" ]; then
      warn "$username" "$(dim 'not present — nothing to delete')"
      continue
    fi
    _split_resp "$(api DELETE "/v2.0/Users/$id")"
    case "$RESP_STATUS" in
      200|204) ok   "$username" "$(dim "deleted (id=$id)")" ;;
      404)     warn "$username" "$(dim 'already gone')" ;;
      *)       fail "$username" "HTTP $RESP_STATUS"
               printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
                 || printf '      %s\n' "$RESP_BODY" ;;
    esac
  done
  # Attribute definitions are left in place on purpose: they are tenant schema,
  # they hold no user data, and re-running the import needs them.
  echo
  echo "$(dim 'Attribute definitions were left in place (tenant schema, no user data).')"
}

# ==========================================================================
# main
# ==========================================================================
echo
echo "$(dim 'tenant  ')" "$TENANT_URL"
echo "$(dim 'source  ')" "$CSV ($USER_COUNT users)"
[ "$DRY_RUN" = true ] && echo "$(dim 'mode    ')" "$(yellow 'dry-run — no requests will be sent')"

[ "$DRY_RUN" = false ] && get_token

if [ "$DO_DELETE" = true ]; then
  delete_users
else
  [ "$DO_ATTRS" = true ] && create_attrs
  [ "$DO_USERS" = true ] && create_users
fi

echo
if [ "$DRY_RUN" = true ]; then
  echo "$(dim 'Dry run only — nothing was sent to the tenant.')"
else
  echo "$(green 'Done.') Verify the result end to end with:"
  echo "  $(dim './mint-verify-token.sh alice | cut -d. -f2 | base64 -d 2>/dev/null | jq .')"
  echo "  $(dim './verify-ibm-verify-token-exchange.sh')"
  echo
  echo "$(dim 'Custom attributes reach the token only once the tenant'"'"'s clients map them')"
  echo "$(dim 'as claims. That mapping is client config, not user data, and this script')"
  echo "$(dim 'does not touch it — check roles/permissions/teams/gh_permissions appear in')"
  echo "$(dim 'the decoded token above before running the walkthrough.')"
fi
