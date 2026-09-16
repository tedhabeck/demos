#!/usr/bin/env bash
# Provision the demo's OAuth clients into an IBM Verify tenant from
# verify/clients.csv, using keycloak/realm-export.json as the model.
#
# Sibling of import-verify-users.sh: that script creates the four personas, this
# one creates the clients that turn their attributes into token claims. RUN THE
# USER IMPORTER FIRST — the default entitlement model grants each persona
# sign-on access by SCIM id, so the users must already exist. Together
# they close decision D5 in
# docs/brainstorms/2026-08-31-ibm-verify-idp-requirements.md ("tenant setup is
# documented, not automated") — this half is the part verify/README.md still
# listed as manual: "It also does not create the two OAuth clients, enable ROPC,
# or set the JWT access-token format."
#
# Usage:
#   ./import-verify-clients.sh                  # create the clients
#   ./import-verify-clients.sh --dry-run        # print the payloads, send nothing
#   ./import-verify-clients.sh --discover       # show tenant facts, create nothing
#   ./import-verify-clients.sh --csv other.csv  # a different client source
#   ./import-verify-clients.sh --no-write-back  # do not touch post_deploy_variables.json
#   ./import-verify-clients.sh --all-users      # entitle ALL tenant users, not just the personas
#   ./import-verify-clients.sh --no-entitle     # skip entitlement entirely
#   ./import-verify-clients.sh --delete         # remove the CSV's clients
#
# Requires: curl, jq, python3 (CSV parsing only — no third-party packages).
#
# ---------------------------------------------------------------------------
# The admin API client needs one more entitlement than the user importer
# ---------------------------------------------------------------------------
# The Applications API is entitlement-gated per endpoint, like the Users API:
#
#   manageAppAccessAdmin  ("Manage application lifecycle")  -> POST/GET/DELETE
#                                                              /v1.0/applications
#
# import-verify-users.sh needs manageUsers + manageAttributes. If you built that
# admin client already, ADD manageAppAccessAdmin to it — a 403 here with a valid
# token means exactly that entitlement is missing. Credentials come from
# .env.verify (gitignored) as VERIFY_ADMIN_CLIENT_ID / VERIFY_ADMIN_CLIENT_SECRET.
#
# ---------------------------------------------------------------------------
# Four field-level facts, all confirmed against a live tenant
# ---------------------------------------------------------------------------
# These are the things that cost time to discover; the API reference documents
# none of them completely. Each was verified by creating and deleting a throwaway
# application on praxis-1.verify.ibm.com.
#
# 1. templateId is "998", not "0001". "0001" circulates in community examples
#    and is wrong here; every custom OIDC app on the tenant uses 998. There is
#    no documented enum, so --discover reads the value off the tenant's own
#    applications rather than trusting this default.
#
# 2. accessTokenType (NOT accessTokenFormat) selects JWT, and setting it to
#    "jwt" REQUIRES a signing algorithm or the create fails with:
#      CSIAQ0257 A JSON Web Token (JWT) access token type requires one of the
#                following signing algorithms: [RS256, ...]
#    The field that satisfies it is providers.oidc.properties.idTokenSigningAlg.
#    That name reads like it should only govern the ID token; it does not, and
#    the GET response omits it entirely, so you cannot discover it by reading an
#    existing app back. Without it every create 400s.
#
# 3. Grant types are the STRINGS "true"/"false", not JSON booleans.
#
# 4. Claim mappers are CELx functions, not sourceId references. The API
#    reference describes providers.oidc.token.attributeMappings[] as
#    JWTAttributeMapBean requiring `sourceId` + `targetName`, which implies
#    mapping by attribute ID. The tenant's working clients use a different and
#    undocumented shape — { targetName, function: { custom: <CELx> } } — and
#    that CELx calls user.getCustomValues(<scimName>). See below.
#
# ---------------------------------------------------------------------------
# THE EMPTY-STRING PADDING LIVES HERE, NOT IN THE USER DATA
# ---------------------------------------------------------------------------
# verify/README.md and users.csv both describe a load-bearing trailing "" that
# keeps single-valued claims array-shaped. Worth being precise about where it
# actually comes from, because it changes what breaks if you edit it:
#
#   The tenant stores alice's roles as ["engineer"] — UNPADDED.
#   Her minted token carries  roles: ["engineer", ""] — PADDED.
#
# The pad is injected by the CELx mapper below (`+ ['']`), which is CLIENT
# config. It is not in the SCIM user record. So:
#
#   - Recreating these clients WITHOUT the pad breaks every single-valued
#     persona: Praxis's standard claim mapper reads roles/teams/permissions via
#     Value::as_array (claim_map.rs:222,248), which returns None for a JSON
#     scalar. subject.roles comes back EMPTY, require(role.hr) fails, and it
#     presents as a policy deny rather than the config fault it is.
#   - The cost, accepted knowingly: "" becomes a real set member and appears in
#     audit records and X-Policy-* output.
#
# Remove the pad from PAD_CEL only once the upstream scalar->single-element-vec
# fallback lands, and then from the mappers on the tenant too.
#
# ---------------------------------------------------------------------------
# getCustomValues() takes the scimName, which is not always the display name
# ---------------------------------------------------------------------------
# The CELx calls user.getCustomValues("<scimName>"). On this tenant the
# gh_permissions attribute has scimName "ghpermissions" — no underscore — so a
# mapper written against the display name silently yields no values, and
# scenario 4's exchange loses its permissions claim with no error anywhere.
#
# This script therefore RESOLVES each claim's scimName from /v1.0/attributes at
# run time instead of assuming name == scimName. Run --discover to see the
# mapping it will use.
#
# ---------------------------------------------------------------------------
# Application entitlement — the step that makes ROPC actually work
# ---------------------------------------------------------------------------
# Creating the application is NOT sufficient to mint. A client with correct
# grants, JWT tokens and claim mappers still rejects every password grant with:
#
#   CSIAQ0279E Only entitled users can single sign-on to the application.
#              You must request for application access.
#
# Application entitlement is a SEPARATE resource, not a field on the application:
#
#   POST /v1.0/owner/applications/{id}/entitlements
#   { "birthRightAccess": <bool>, "requestAccess": <bool>,
#     "additions": [ { "assignee": {"subjectId": <scim id>,
#                                   "subjectType": "user"},
#                      "grantType": "BRT" } ] }
#
# Entitlement: manageAppAccessAdmin (which this script already needs) or
# manageAppAccessOwner. GET on the same path reads the current state back.
#
# This is why it cannot be found by diffing application JSON: `birthRightAccess`
# reads back as null on GET /v1.0/applications/{id} — write-only there, the same
# trap as idTokenSigningAlg — and the grants live under /v1.0/owner/... instead.
#
# TWO ACCESS MODELS, both verified on the live tenant:
#
#   explicit (default here)  birthRightAccess=false + one addition per persona.
#                            Only the named users may sign on. This is how the
#                            owner's praxis-identity-1 is already configured
#                            (alice, bob, charlie, eve, each grantType BRT).
#                            Verified: alice mints, bob is denied.
#
#   birthright (--all-users) birthRightAccess=true. Every user in the tenant is
#                            entitled by default — the console's "Automatic
#                            access for all users and groups". Fewer calls, no
#                            SCIM lookups, but it grants tenant-wide.
#
# Explicit is the default because it matches both the existing tenant and the
# demo's own argument: four personas whose differences are the point. A client
# any user can mint from undercuts eve-vs-bob. Use --all-users on a throwaway
# tenant where that does not matter.
#
# Only clients users authenticate TO need this (role=mint). The exchange client
# acts on a subject_token and the audience placeholders are never authenticated
# to, so neither is entitled — and neither needs to be.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CSV="$SCRIPT_DIR/clients.csv"
DRY_RUN=false
DO_DELETE=false
DISCOVER_ONLY=false
WRITE_BACK=true
# Entitlement model for role=mint clients. Explicit per-user grants by default;
# --all-users switches to tenant-wide birthright access. --no-entitle skips it
# entirely for a tenant that manages application access out of band.
ALL_USERS=false
DO_ENTITLE=true
# Overridable so a tenant using a different custom-application template can be
# targeted without editing the script; --discover reports what the tenant uses.
TEMPLATE_ID="${VERIFY_APP_TEMPLATE_ID:-998}"
SIGNING_ALG="${VERIFY_ACCESS_TOKEN_SIGNING_ALG:-RS256}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)       DRY_RUN=true ;;
    --discover)      DISCOVER_ONLY=true ;;
    --delete)        DO_DELETE=true ;;
    --no-write-back) WRITE_BACK=false ;;
    --all-users)     ALL_USERS=true ;;
    --no-entitle)    DO_ENTITLE=false ;;
    --csv)           CSV="${2:?--csv needs a path}"; shift ;;
    --template-id)   TEMPLATE_ID="${2:?--template-id needs a value}"; shift ;;
    # Print just the synopsis (down to the "Requires:" line), not the whole
    # rationale essay in the header.
    -h|--help)       sed -n '2,/^# Requires:/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
[ -f "$CSV" ] || die "client source not found: $CSV"

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

The Applications API needs an API client with the 'manageAppAccessAdmin'
entitlement ("Manage application lifecycle"). This is deliberately NOT one of
the demo clients — see the header of this script.

  1. Verify admin console -> Security -> API access -> Add API client
  2. Grant: "Manage application lifecycle"
     (add it to the same client import-verify-users.sh uses, which already has
      "Manage users and groups" + "Manage attributes")
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
# The Applications API is plain JSON, unlike the SCIM Users API.
api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -o - -w $'\n%{http_code}' -X "$method" "${TENANT_URL}${path}"
    -H "Authorization: Bearer $ACCESS_TOKEN"
    -H "Accept: application/json")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" --data "$body")
  fi
  curl "${args[@]}"
}

# Split "<body>\n<status>" from api() into the globals RESP_BODY / RESP_STATUS.
_split_resp() {
  RESP_STATUS="${1##*$'\n'}"
  RESP_BODY="${1%$'\n'*}"
}

# --- CSV -> JSON ----------------------------------------------------------
# Parsed with python3's csv module rather than IFS=, read: it handles quoting
# and CRLF correctly, and it lets the '##' comment convention in clients.csv
# work. Columns are read BY HEADER NAME, so the CSV stays reorderable.
csv_json() {
  python3 - "$CSV" <<'PY'
import csv, json, sys

REQUIRED = ["name", "role"]
FLAGS    = ["ropc", "client_creds", "token_exchange"]
LISTS    = ["audiences", "claims"]
OPTIONAL = ["pdv_id_key", "pdv_secret_key"]
ROLES    = {"mint", "exchange", "audience"}

with open(sys.argv[1], newline="") as fh:
    # '##' lines are documentation, not data. Blank lines are skipped so the
    # file can be visually grouped.
    rows = [ln for ln in fh if not ln.lstrip().startswith("##") and ln.strip()]

reader = csv.DictReader(rows)
missing = [c for c in REQUIRED + FLAGS if c not in (reader.fieldnames or [])]
if missing:
    sys.exit(f"clients.csv is missing required column(s): {', '.join(missing)}\n"
             f"found: {', '.join(reader.fieldnames or [])}")

def flag(row, key, line):
    raw = (row.get(key) or "").strip().lower()
    if raw in ("true", "yes", "1"):  return True
    if raw in ("false", "no", "0", ""): return False
    sys.exit(f"row {line}: {key} must be true or false, got {raw!r}")

out, seen = [], set()
for i, row in enumerate(reader, start=2):
    c = {k: (row.get(k) or "").strip() for k in REQUIRED + OPTIONAL}
    if not c["name"]:
        sys.exit(f"row {i}: empty name")
    if c["name"] in seen:
        sys.exit(f"row {i}: duplicate client name {c['name']!r}")
    seen.add(c["name"])
    if c["role"] not in ROLES:
        sys.exit(f"row {i}: role must be one of {sorted(ROLES)}, got {c['role']!r}")
    for k in FLAGS:
        c[k] = flag(row, k, i)
    for k in LISTS:
        raw = (row.get(k) or "").strip()
        c[k] = [v.strip() for v in raw.split("|") if v.strip()]
    # Verify rejects an application with every grant type disabled:
    #   CSIAQ0032 Grant type information is required.
    # Catch it here so the message names the row rather than surfacing as a raw
    # API error four requests later.
    if not any(c[k] for k in FLAGS):
        sys.exit(f"row {i}: {c['name']!r} enables no grant type, which Verify "
                 f"rejects (CSIAQ0032). Even a placeholder needs one — "
                 f"client_creds=true is the narrowest.")
    # A write-back needs both halves or neither; a half-written pair would leave
    # post_deploy_variables.json describing a client that cannot authenticate.
    if bool(c["pdv_id_key"]) != bool(c["pdv_secret_key"]):
        sys.exit(f"row {i}: pdv_id_key and pdv_secret_key must both be set or both be empty")
    out.append(c)

if not out:
    sys.exit("clients.csv contains no client rows")
json.dump(out, sys.stdout)
PY
}

CLIENTS_JSON="$(csv_json)" || die "failed to parse $CSV"
CLIENT_COUNT=$(printf '%s' "$CLIENTS_JSON" | jq 'length')

# --- claim mappers --------------------------------------------------------
# The CELx body for one padded, array-shaped claim. %s is the scimName that
# user.getCustomValues() looks up — NOT necessarily the display name.
#
# The `+ ['']` is the load-bearing pad. See the header before touching it.
PAD_CEL='statements:
  - context: values := user.getCustomValues("%s")
  - context: "safeValues := context.values == null ? [] : context.values"
  - context: "paddedValues := context.safeValues + ['\'''\'']"
  - return: context.paddedValues'

# Resolved at run time into "claim=scimName" pairs by resolve_scim_names().
declare -a SCIM_MAP=()

scim_name_for() {
  local claim="$1" entry
  # ${arr[@]} on an empty array trips `set -u` on bash 3.2 (macOS), so guard it.
  if [ "${#SCIM_MAP[@]}" -gt 0 ]; then
    for entry in "${SCIM_MAP[@]}"; do
      [ "${entry%%=*}" = "$claim" ] && { printf '%s' "${entry#*=}"; return 0; }
    done
  fi
  # Unresolved. On a real run resolve_scim_names() has already made this fatal,
  # so this is the --dry-run path: use the display name, which is correct for
  # every claim whose scimName matches it, and is reported as an assumption.
  printf '%s' "$claim"
}

# Read /v1.0/attributes once and record each claim's scimName. A claim whose
# attribute does not exist is fatal: the mapper would be created successfully
# and then silently yield nothing, which surfaces as a policy deny.
resolve_scim_names() {
  local claims attrs_json
  claims=$(printf '%s' "$CLIENTS_JSON" | jq -r '[.[].claims[]] | unique | .[]')
  [ -n "$claims" ] || return 0

  _split_resp "$(api GET "/v1.0/attributes?limit=200")"
  [ "$RESP_STATUS" = "200" ] || die "could not list /v1.0/attributes (HTTP $RESP_STATUS) — the admin client needs the 'manageAttributes' entitlement"
  attrs_json="$RESP_BODY"

  local claim scim
  while IFS= read -r claim; do
    [ -n "$claim" ] || continue
    # The endpoint returns a bare array on this tenant; tolerate a wrapped
    # shape too so a differently-versioned tenant does not silently resolve
    # every claim to its fallback.
    scim=$(printf '%s' "$attrs_json" | jq -r --arg n "$claim" '
      (if type == "array" then . else (._embedded.attributes // .attributes // []) end)
      | map(select(.name == $n))
      | (.[0].schemaAttribute.scimName // .[0].scimName // empty)')
    if [ -z "$scim" ]; then
      fail "$claim" "no custom attribute named '$claim' on the tenant"
      echo "$(dim '      Run ./verify/import-verify-users.sh --attrs-only first: a mapper for')" >&2
      echo "$(dim '      an undefined attribute is created happily and then yields nothing,')" >&2
      echo "$(dim '      which presents as a policy deny rather than a config error.')" >&2
      die "cannot build a claim mapper for '$claim'"
    fi
    SCIM_MAP+=("$claim=$scim")
  done <<< "$claims"
}

# --- payload --------------------------------------------------------------
# Build the POST /v1.0/applications body for the client at index $1.
app_payload() {
  local i="$1" claim scim cel
  local mappers='[]'

  while IFS= read -r claim; do
    [ -n "$claim" ] || continue
    scim="$(scim_name_for "$claim")"
    # shellcheck disable=SC2059
    cel="$(printf "$PAD_CEL" "$scim")"
    mappers=$(printf '%s' "$mappers" | jq --arg t "$claim" --arg c "$cel" \
      '. + [{targetName: $t, function: {custom: $c}}]')
  done <<< "$(printf '%s' "$CLIENTS_JSON" | jq -r ".[$i].claims[]?")"

  printf '%s' "$CLIENTS_JSON" | jq \
    --argjson i "$i" \
    --arg template "$TEMPLATE_ID" \
    --arg alg "$SIGNING_ALG" \
    --argjson mappers "$mappers" '
    .[$i] as $c
    | ($c.ropc           | if . then "true" else "false" end) as $ropc
    | ($c.client_creds   | if . then "true" else "false" end) as $cc
    | ($c.token_exchange | if . then "true" else "false" end) as $te
    | {
        name: $c.name,
        templateId: $template,
        # false would leave the application in draft and unable to issue tokens.
        applicationState: true,
        description: ("Policy-engine demo (" + $c.role + ") — created by verify/import-verify-clients.sh from keycloak/realm-export.json"),
        providers: {
          # `sso` is required even for a pure OIDC app. userOptions:"oidc" is
          # what the tenant'"'"'s own working clients carry, and it satisfies the
          # requirement without inventing a domainName.
          sso: { userOptions: "oidc" },
          oidc: {
            properties: {
              # Grant types are the STRINGS "true"/"false", not booleans.
              grantTypes: {
                ropc: $ropc,
                clientCredentials: $cc,
                tokenExchange: $te,
                authorizationCode: "false",
                implicit: "false",
                jwtBearer: "false",
                deviceFlow: "false",
                policyAuth: "false"
              },
              # Unused by the demo (no browser leg) but Verify wants the field
              # present; matches what the tenant'"'"'s working clients carry.
              redirectUris: ["https://localhost:8443"],
              # REQUIRED whenever accessTokenType is "jwt", despite the name
              # suggesting it only governs the ID token. Omit it and every
              # create fails with CSIAQ0257. See the script header.
              idTokenSigningAlg: $alg,
              doNotGenerateClientSecret: false,
              additionalConfig: {
                # Without this, ROPC on a freshly created client fails with
                #   CSIAQ0279E Only entitled users can single sign-on to the
                #              application. You must request for application access.
                # even though the client, its grants and its mappers are all
                # correct — Verify gates sign-on on per-user application
                # entitlement. `true` means "every user in the tenant may use
                # this client", which is what the demo minting client needs and
                # what the tenant version already carries.
                #
                # Only the minting client needs it: no user ever authenticates
                # to the exchange client (it acts on a subject_token) or to the
                # audience placeholders, so they leave it false and stay
                # correspondingly narrow.
                useUserDefaultEntitlements: ($c.role == "mint")
              }
            },
            token: {
              # accessTokenType, NOT accessTokenFormat. Praxis validates the
              # access token as a JWT against the tenant JWKS, so "default"
              # (opaque) would fail at identity.
              accessTokenType: "jwt",
              audiences: $c.audiences,
              attributeMappings: $mappers
            }
          }
        },
        # Required at the top level; the demo provisions no accounts downstream.
        provisioning: {}
      }'
}

# ==========================================================================
# discovery
# ==========================================================================
# The two facts this script cannot safely assume: which template a custom OIDC
# app uses, and each claim'"'"'s scimName. Both are read off the tenant.
discover() {
  echo
  echo "$(dim 'Tenant facts') $(dim "-> ${TENANT_URL}")"

  _split_resp "$(api GET "/v1.0/applications?limit=200")"
  if [ "$RESP_STATUS" != "200" ]; then
    fail "applications" "HTTP $RESP_STATUS"
    [ "$RESP_STATUS" = "403" ] && echo "$(dim "      the admin client lacks the 'manageAppAccessAdmin' entitlement")"
    die "could not list applications"
  fi

  # api() overwrites RESP_BODY on every call, and the loop below issues one GET
  # per application, so keep the listing.
  RESP_BODY_LIST="$RESP_BODY"

  local tmpl
  tmpl=$(printf '%s' "$RESP_BODY" | jq -r '
    [._embedded.applications[]?.templateId] | map(select(. != null))
    | group_by(.) | map({t: .[0], n: length}) | sort_by(-.n)
    | map("\(.t) (\(.n) app\(if .n == 1 then "" else "s" end))") | join(", ")')
  ok "templateId in use" "$(dim "${tmpl:-none found}")"
  if [ -n "$tmpl" ] && ! printf '%s' "$tmpl" | grep -q "^$TEMPLATE_ID "; then
    warn "templateId default" "$(dim "using $TEMPLATE_ID; override with --template-id if that is wrong")"
  fi

  echo
  echo "$(dim 'Existing applications')"
  # The LIST response omits clientId — only the per-application GET carries it,
  # so fetch each one rather than printing a column of "-".
  local aid aname acid n who
  while IFS=$'\t' read -r aid aname; do
    [ -n "$aid" ] || continue
    _split_resp "$(api GET "/v1.0/applications/$aid")"
    acid=$(printf '%s' "$RESP_BODY" | jq -r '.providers.oidc.properties.clientId // "-"' 2>/dev/null || echo "-")
    printf '  %-34s %s\n' "$aname" "$(dim "$acid")"
  done <<< "$(printf '%s' "$RESP_BODY_LIST" | jq -r '._embedded.applications[]?
    | "\(._links.self.href | sub("^.*/applications/"; ""))\t\(.name)"')"

  echo
  echo "$(dim 'Application entitlement') $(dim '(who may sign on — GET /v1.0/owner/applications/<id>/entitlements)')"
  while IFS=$'\t' read -r aid aname; do
    [ -n "$aid" ] || continue
    _split_resp "$(api GET "/v1.0/owner/applications/$aid/entitlements")"
    if [ "$RESP_STATUS" != "200" ]; then
      warn "$aname" "$(dim "could not read (HTTP $RESP_STATUS)")"
      continue
    fi
    printf '%s' "$RESP_BODY" | jq -e '.birthRightAccess == true' >/dev/null 2>&1 \
      && { ok "$aname" "$(dim 'all tenant users (birthright)')"; continue; }
    n=$(printf '%s' "$RESP_BODY" | jq -r '[.entitlements[]?] | length')
    if [ "$n" = "0" ]; then
      warn "$aname" "$(dim 'nobody entitled (fine unless users authenticate to it)')"
    else
      who=$(printf '%s' "$RESP_BODY" | jq -r '[.entitlements[]?.assignee.userName] | join(", ")')
      ok "$aname" "$(dim "$n grant(s): $who")"
    fi
  done <<< "$(printf '%s' "$RESP_BODY_LIST" | jq -r '._embedded.applications[]?
    | "\(._links.self.href | sub("^.*/applications/"; ""))\t\(.name)"')"

  echo
  echo "$(dim 'Claim -> scimName') $(dim '(what the CELx mappers will call)')"
  local entry claim scim
  [ "${#SCIM_MAP[@]}" -gt 0 ] || { warn "claims" "$(dim 'no claim mappers configured in the CSV')"; return 0; }
  for entry in "${SCIM_MAP[@]}"; do
    claim="${entry%%=*}"; scim="${entry#*=}"
    if [ "$claim" = "$scim" ]; then
      ok "$claim" "$(dim "getCustomValues(\"$scim\")")"
    else
      warn "$claim" "$(dim "getCustomValues(\"$scim\") — scimName differs from the display name")"
    fi
  done
}

# ==========================================================================
# clients
# ==========================================================================
# Look up an application by name -> "<id>\t<clientId>". Makes create idempotent
# and drives --delete. Filtered client-side: the search syntax for this endpoint
# is undocumented, and a wrong filter silently returns everything.
find_app() {
  local name="$1" id
  _split_resp "$(api GET "/v1.0/applications?limit=200")"
  [ "$RESP_STATUS" = "200" ] || return 1
  id=$(printf '%s' "$RESP_BODY" | jq -r --arg n "$name" '
    [._embedded.applications[]? | select(.name == $n)
     | (._links.self.href | sub("^.*/applications/"; ""))] | .[0] // empty')
  [ -n "$id" ] || return 1
  # The list response has no clientId — only the per-application GET does.
  _split_resp "$(api GET "/v1.0/applications/$id")"
  printf '%s\t%s\n' "$id" \
    "$(printf '%s' "$RESP_BODY" | jq -r '.providers.oidc.properties.clientId // "-"' 2>/dev/null || echo '-')"
}

# The 201 response carries only _links.self.href — the generated clientId and
# clientSecret are NOT in it. Read them back from the created application.
fetch_credentials() {
  local id="$1"
  _split_resp "$(api GET "/v1.0/applications/$id")"
  [ "$RESP_STATUS" = "200" ] || return 1
  printf '%s' "$RESP_BODY" | jq -r '
    "\(.providers.oidc.properties.clientId // "")\t\(.providers.oidc.properties.clientSecret // "")"'
}

# name<TAB>id<TAB>secret for every client created in this run, consumed by
# write_back(). Kept in memory: secrets do not belong on disk outside the
# gitignored post_deploy_variables.json.
declare -a CREATED=()
# Clients created in this run whose entitlement did NOT get granted — skipped
# with --no-entitle, or the grant failed. These cannot mint until it is fixed.
declare -a NEEDS_ENTITLEMENT=()

create_clients() {
  echo
  echo "$(dim 'Applications') $(dim "-> ${TENANT_URL}/v1.0/applications")"
  local i name role body existing id cid secret

  for i in $(seq 0 $((CLIENT_COUNT - 1))); do
    name=$(printf '%s' "$CLIENTS_JSON" | jq -r ".[$i].name")
    role=$(printf '%s' "$CLIENTS_JSON" | jq -r ".[$i].role")
    body="$(app_payload "$i")"

    if [ "$DRY_RUN" = true ]; then
      ok "$name" "$(dim "$role (dry-run)")"
      printf '%s\n' "$body" | jq . | sed 's/^/      /'
      continue
    fi

    # Creating a second application with the same name would leave two clients
    # and no way to tell which one the config refers to.
    if existing=$(find_app "$name") && [ -n "$existing" ]; then
      warn "$name" "$(dim "exists (client_id=$(printf '%s' "$existing" | cut -f2)) — left unchanged; use --delete to replace")"
      continue
    fi

    _split_resp "$(api POST "/v1.0/applications" "$body")"
    case "$RESP_STATUS" in
      201)
        id=$(printf '%s' "$RESP_BODY" | jq -r '._links.self.href // empty' | sed 's|^.*/applications/||')
        if [ -z "$id" ]; then
          fail "$name" "created but the response carried no application id"
          die "cannot read back credentials for '$name'"
        fi
        if ! creds=$(fetch_credentials "$id"); then
          fail "$name" "created (id=$id) but its credentials could not be read back"
          die "created '$name' but cannot read its client_id — check the console"
        fi
        cid=$(printf '%s' "$creds" | cut -f1)
        secret=$(printf '%s' "$creds" | cut -f2)
        ok "$name" "$(dim "$role — client_id=${cid:-?}")"
        CREATED+=("$name"$'\t'"$cid"$'\t'"$secret")
        # A client users authenticate TO is gated on application entitlement,
        # which is a separate resource from the application itself. Grant it now
        # or the client cannot mint (CSIAQ0279E). See the script header.
        if [ "$role" = "mint" ]; then
          if [ "$DO_ENTITLE" = true ]; then
            if ! entitle_app "$id" "$name"; then
              NEEDS_ENTITLEMENT+=("$name")
            fi
          else
            NEEDS_ENTITLEMENT+=("$name")
          fi
        fi
        ;;
      400)
        fail "$name" "HTTP 400"
        printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
          || printf '      %s\n' "$RESP_BODY"
        # The two 400s that actually happen, and what they mean.
        case "$RESP_BODY" in
          *CSIAQ0257*) echo "$(dim '      A JWT access token needs idTokenSigningAlg — see the script header.')" ;;
          *) echo "$(dim "      Often a templateId the tenant does not know. Run --discover to see")"
             echo "$(dim "      which templateId its own applications use.")" ;;
        esac
        die "client '$name' rejected" ;;
      403)
        fail "$name" "HTTP 403 — the API client lacks the 'manageAppAccessAdmin' entitlement"
        die "insufficient entitlements" ;;
      *)
        fail "$name" "HTTP $RESP_STATUS"
        printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
          || printf '      %s\n' "$RESP_BODY"
        die "unexpected response creating '$name'" ;;
    esac
  done
}

delete_clients() {
  echo
  echo "$(yellow 'Deleting') $(dim "the ${CLIENT_COUNT} clients in $(basename "$CSV") from ${TENANT_URL}")"
  local i name found id
  for i in $(seq 0 $((CLIENT_COUNT - 1))); do
    name=$(printf '%s' "$CLIENTS_JSON" | jq -r ".[$i].name")

    if [ "$DRY_RUN" = true ]; then
      ok "$name" "$(dim '(dry-run) would DELETE /v1.0/applications/<id>')"
      continue
    fi

    if ! found=$(find_app "$name") || [ -z "$found" ]; then
      warn "$name" "$(dim 'not present — nothing to delete')"
      continue
    fi
    id=$(printf '%s' "$found" | cut -f1)
    _split_resp "$(api DELETE "/v1.0/applications/$id")"
    case "$RESP_STATUS" in
      200|204) ok   "$name" "$(dim "deleted (id=$id)")" ;;
      404)     warn "$name" "$(dim 'already gone')" ;;
      *)       fail "$name" "HTTP $RESP_STATUS"
               printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
                 || printf '      %s\n' "$RESP_BODY" ;;
    esac
  done
  echo
  echo "$(dim 'post_deploy_variables.json still names the deleted clients. Re-run without')"
  echo "$(dim '--delete to recreate them and refresh the ids there.')"
}

# ==========================================================================
# application entitlement
# ==========================================================================
# Resolve a userName -> SCIM id, needed for an explicit grant's subjectId.
scim_user_id() {
  local username="$1" filter
  filter="userName%20eq%20%22${username}%22"
  _split_resp "$(api_scim GET "/v2.0/Users?filter=${filter}")"
  [ "$RESP_STATUS" = "200" ] || return 1
  printf '%s' "$RESP_BODY" | jq -r '.Resources[0].id // empty'
}

# The Users API speaks SCIM; the Applications API speaks plain JSON. Same token,
# different Accept, so entitlement work needs both.
api_scim() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -o - -w $'\n%{http_code}' -X "$method" "${TENANT_URL}${path}"
    -H "Authorization: Bearer $ACCESS_TOKEN"
    -H "Accept: application/scim+json; charset=utf-8")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/scim+json; charset=utf-8" -d "$body")
  fi
  curl "${args[@]}"
}

# The personas to entitle, read from users.csv so this script and the user
# importer cannot disagree about who the demo's users are.
entitle_usernames() {
  local users_csv="$SCRIPT_DIR/users.csv"
  [ -f "$users_csv" ] || return 0
  python3 - "$users_csv" <<'PY_INNER'
import csv, sys
with open(sys.argv[1], newline="") as fh:
    rows = [l for l in fh if not l.lstrip().startswith("##") and l.strip()]
for row in csv.DictReader(rows):
    name = (row.get("username") or "").strip()
    if name:
        print(name)
PY_INNER
}

# Grant sign-on entitlement for one application id.
# Without this a role=mint client rejects every password grant with CSIAQ0279E.
entitle_app() {
  local id="$1" name="$2" body payload_desc

  if [ "$ALL_USERS" = true ]; then
    body='{"birthRightAccess":true,"requestAccess":false}'
    payload_desc="all tenant users (birthright)"
  else
    # Explicit grants: one addition per persona, each needing a SCIM id.
    local -a additions=()
    local u uid missing=""
    while IFS= read -r u; do
      [ -n "$u" ] || continue
      if uid=$(scim_user_id "$u") && [ -n "$uid" ]; then
        additions+=("$(jq -nc --arg i "$uid" '{assignee:{subjectId:$i,subjectType:"user"},grantType:"BRT"}')")
      else
        missing="${missing:+$missing, }$u"
      fi
    done <<< "$(entitle_usernames)"

    if [ -n "$missing" ]; then
      warn "$name" "$(dim "not entitled: user(s) not on the tenant — $missing")"
      echo "$(dim '      Run ./verify/import-verify-users.sh first, then re-run with --users-only')" >&2
    fi
    if [ "${#additions[@]}" -eq 0 ]; then
      fail "$name" "no demo users found to entitle"
      echo "$(dim '      Without an entitlement this client cannot mint (CSIAQ0279E).')" >&2
      echo "$(dim '      Create the users first, or use --all-users / --no-entitle.')" >&2
      return 1
    fi
    body=$(printf '%s\n' "${additions[@]}" | jq -sc \
      '{birthRightAccess:false,requestAccess:false,additions:.}')
    payload_desc="${#additions[@]} demo user(s)"
  fi

  if [ "$DRY_RUN" = true ]; then
    ok "$name" "$(dim "would entitle $payload_desc (dry-run)")"
    return 0
  fi

  _split_resp "$(api POST "/v1.0/owner/applications/$id/entitlements" "$body")"
  case "$RESP_STATUS" in
    200|201|204) ok "$name" "$(dim "entitled: $payload_desc")" ;;
    403) fail "$name" "HTTP 403 — needs manageAppAccessAdmin or manageAppAccessOwner"
         return 1 ;;
    *)   fail "$name" "entitlement failed: HTTP $RESP_STATUS"
         printf '%s\n' "$RESP_BODY" | jq . 2>/dev/null | sed 's/^/      /' \
           || printf '      %s\n' "$RESP_BODY"
         echo "$(dim '      The client exists but cannot mint until this succeeds (CSIAQ0279E).')" >&2
         return 1 ;;
  esac
}

# ==========================================================================
# write-back
# ==========================================================================
# Verify GENERATES the client_id and client_secret, so unlike the Keycloak realm
# export nothing downstream can hardcode them. mint-verify-token.sh and
# verify-ibm-verify-token-exchange.sh both read them from
# post_deploy_variables.json, so a freshly provisioned tenant is only usable
# once they land there. That file is gitignored (it holds live credentials).
#
# policy-verify-opa.yaml needs no editing here: it is GENERATED from
# policy-verify-opa.yaml.tmpl by ../render-verify-config.sh, which reads the
# exchange client_id from GATEWAY_CLIENT_ID in this same file (or from
# $VERIFY_GATEWAY_CLIENT_ID). restart.sh renders it on every Verify run, so a
# write-back here is all that is needed for the new id to reach the gateway.
write_back() {
  [ "${#CREATED[@]}" -gt 0 ] || return 0

  echo
  echo "$(dim 'Credentials') $(dim "-> $(basename "$PDV")")"

  local entry name cid secret id_key secret_key updated=0
  local tmp; tmp="$(mktemp)"
  cp "$PDV" "$tmp"

  for entry in "${CREATED[@]}"; do
    name="$(printf '%s' "$entry" | cut -f1)"
    cid="$(printf '%s' "$entry" | cut -f2)"
    secret="$(printf '%s' "$entry" | cut -f3)"

    id_key=$(printf '%s' "$CLIENTS_JSON" | jq -r --arg n "$name" '.[] | select(.name==$n) | .pdv_id_key')
    secret_key=$(printf '%s' "$CLIENTS_JSON" | jq -r --arg n "$name" '.[] | select(.name==$n) | .pdv_secret_key')
    [ -n "$id_key" ] || { ok "$name" "$(dim 'no write-back configured')"; continue; }

    if [ -z "$cid" ]; then
      warn "$name" "$(dim 'no client_id read back — not written')"
      continue
    fi
    # A client_id without its secret cannot authenticate; writing half the pair
    # would produce a config that fails at the token endpoint instead of here.
    if [ -z "$secret" ]; then
      warn "$name" "$(dim "client_id known but secret not returned — set $secret_key by hand from the console")"
    fi

    jq --arg ik "$id_key" --arg iv "$cid" \
       --arg sk "$secret_key" --arg sv "$secret" '
      .variables[$ik] = $iv
      | if $sv == "" then . else .variables[$sk] = $sv end' "$tmp" > "$tmp.new" \
      && mv "$tmp.new" "$tmp"
    ok "$name" "$(dim "$id_key${secret:+ + $secret_key}")"
    updated=$((updated + 1))
  done

  if [ "$updated" -gt 0 ]; then
    # Only now overwrite the real file, so a failure part-way leaves it intact.
    mv "$tmp" "$PDV"
  else
    rm -f "$tmp"
  fi
}

# ==========================================================================
# main
# ==========================================================================
echo
echo "$(dim 'tenant  ')" "$TENANT_URL"
echo "$(dim 'source  ')" "$CSV ($CLIENT_COUNT clients)"
echo "$(dim 'template')" "$TEMPLATE_ID"
if [ "$DRY_RUN" = true ]; then
  echo "$(dim 'mode    ')" "$(yellow 'dry-run — no requests will be sent')"
fi

if [ "$DRY_RUN" = false ]; then
  get_token
  resolve_scim_names
else
  # No tenant call, so scimNames cannot be resolved. Say so where the payloads
  # are about to be printed rather than letting getCustomValues("<display name>")
  # look authoritative.
  echo "$(dim 'note    ')" "$(yellow 'claim mappers below assume scimName == claim name (unverifiable offline)')"
fi

if [ "$DISCOVER_ONLY" = true ]; then
  [ "$DRY_RUN" = true ] && die "--discover reads the tenant; it cannot be combined with --dry-run"
  discover
  echo
  echo "$(dim 'Discovery only — nothing was created.')"
  exit 0
fi

if [ "$DO_DELETE" = true ]; then
  delete_clients
else
  create_clients
  if [ "$WRITE_BACK" = true ]; then
    write_back
  fi
fi

echo
if [ "$DRY_RUN" = true ]; then
  echo "$(dim 'Dry run only — nothing was sent to the tenant.')"
  echo "$(dim 'Claim mappers used the display name as the scimName; the real run resolves')"
  echo "$(dim 'it from the tenant, which can differ (gh_permissions -> ghpermissions).')"
elif [ "$DO_DELETE" = false ]; then
  echo "$(green 'Done.') Confirm the claims actually reach a token:"
  echo "  $(dim './mint-verify-token.sh alice | cut -d. -f2 | base64 -d 2>/dev/null | jq .')"
  echo "  $(dim './verify-ibm-verify-token-exchange.sh')"
  echo
  echo "$(dim 'Expect roles/permissions/teams/gh_permissions as ARRAYS with a trailing "".')"
  echo "$(dim 'A scalar or missing claim means a mapper did not resolve — check --discover.')"

  if [ "${#NEEDS_ENTITLEMENT[@]}" -gt 0 ]; then
    echo
    echo "$(yellow 'NOT ENTITLED') $(dim '— these clients cannot mint yet:')"
    for entry in "${NEEDS_ENTITLEMENT[@]}"; do echo "  $(dim "• $entry")"; done
    echo
    if [ "$DO_ENTITLE" = false ]; then
      echo "$(dim '  Skipped because --no-entitle was passed. Re-run without it, or grant')"
      echo "$(dim '  access in the console under Applications -> <client> -> Entitlements.')"
    else
      echo "$(dim '  The grant failed — see the error above. Until it succeeds the password')"
      echo "$(dim '  grant returns CSIAQ0279E ("Only entitled users can single sign-on").')"
      echo "$(dim '  Retry, or set it in the console: Applications -> <client> -> Entitlements.')"
    fi
  fi
  gw=$(printf '%s' "$CLIENTS_JSON" | jq -r '.[] | select(.role=="exchange") | .name' | head -1)
  if [ -n "$gw" ] && [ "${#CREATED[@]}" -gt 0 ]; then
    for entry in "${CREATED[@]}"; do
      if [ "$(printf '%s' "$entry" | cut -f1)" = "$gw" ]; then
        echo
        echo "$(dim 'policy-verify-opa.yaml picks this up automatically — it is rendered from')"
        echo "$(dim 'its .tmpl by render-verify-config.sh on every Verify run of restart.sh.')"
        echo "  $(dim "new exchange client_id: $(printf '%s' "$entry" | cut -f2)")"
      fi
    done
  fi
fi
