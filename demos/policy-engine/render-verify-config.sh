#!/usr/bin/env bash
# Render policy-verify-opa.yaml from policy-verify-opa.yaml.tmpl.
#
# The Verify path's tenant URL and exchange client_id are tenant-specific, and
# Verify GENERATES client ids — so a rebuilt tenant invalidates whatever is
# committed. Praxis has no env-var support for `client_id` (only the client
# SECRET has a `client_secret_source: {kind: env_var}` indirection; client_id is
# a plain String read straight into the outbound Basic auth header), so
# substitution has to happen before the gateway reads the file. This script is
# that step.
#
# Usage:
#   ./render-verify-config.sh              # render, skipping an up-to-date file
#   ./render-verify-config.sh --force      # re-render even if up to date
#   ./render-verify-config.sh --check      # verify only; non-zero if stale
#   ./render-verify-config.sh --print      # render to stdout, write nothing
#
# restart.sh calls this automatically for any *verify* GATEWAY_CONFIG, so the
# normal path needs nothing.
#
# Requires: python3 (already required by verify/import-verify-*.sh).
# Deliberately NOT envsubst: that is gettext, absent from a stock macOS and from
# minimal Linux images, and it would substitute every $VAR in the file rather
# than the two intended ones.
#
# ---------------------------------------------------------------------------
# What is and is not substituted
# ---------------------------------------------------------------------------
#   ${VERIFY_TENANT_URL}         default: IBM_VERIFY_TOKEN_ENDPOINT in
#                                post_deploy_variables.json, minus /oauth2/token
#   ${VERIFY_GATEWAY_CLIENT_ID}  default: GATEWAY_CLIENT_ID in that same file
#
# The client SECRET is deliberately absent. It stays a runtime lookup by the
# gateway (client_secret_source: {kind: env_var}), so a live credential never
# lands in a rendered file. Keep it that way: this output is a plain file in the
# working tree, and the gitignore entry is the only thing between it and a commit.
#
# The Keycloak CIBA endpoints in the template are literal localhost URLs and are
# NOT templated — that plugin still points at Keycloak (see the note in the
# template), so templating them would imply a portability that does not exist.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

TMPL="policy-verify-opa.yaml.tmpl"
OUT="policy-verify-opa.yaml"
PDV="post_deploy_variables.json"

FORCE=false
CHECK=false
PRINT=false
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=true ;;
    --check) CHECK=true ;;
    --print) PRINT=true ;;
    -h|--help) sed -n '2,/^# Requires:/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }
die()   { echo "$(red 'fatal:') $*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is required but not on PATH"
[ -f "$TMPL" ] || die "template not found: $TMPL"

# --- resolve the two values ------------------------------------------------
# An already-exported value wins, so a one-off run or CI can override without
# editing any file. Otherwise fall back to post_deploy_variables.json, which is
# what verify/import-verify-clients.sh writes the generated ids into.
TENANT_URL="${VERIFY_TENANT_URL:-}"
CLIENT_ID="${VERIFY_GATEWAY_CLIENT_ID:-}"

if [ -z "$TENANT_URL" ] || [ -z "$CLIENT_ID" ]; then
  [ -f "$PDV" ] || die "$PDV not found, and VERIFY_TENANT_URL / VERIFY_GATEWAY_CLIENT_ID are not both set"
  command -v jq >/dev/null 2>&1 || die "jq is required to read defaults from $PDV (or export both variables)"

  if [ -z "$TENANT_URL" ]; then
    _ep=$(jq -r '.variables.IBM_VERIFY_TOKEN_ENDPOINT // empty' "$PDV")
    [ -n "$_ep" ] || die "IBM_VERIFY_TOKEN_ENDPOINT missing from $PDV; export VERIFY_TENANT_URL instead"
    TENANT_URL="${_ep%/oauth2/token}"
    [ "$TENANT_URL" != "$_ep" ] \
      || die "could not derive a tenant URL from '$_ep' (expected it to end in /oauth2/token)"
  fi
  if [ -z "$CLIENT_ID" ]; then
    CLIENT_ID=$(jq -r '.variables.GATEWAY_CLIENT_ID // empty' "$PDV")
    [ -n "$CLIENT_ID" ] || die "GATEWAY_CLIENT_ID missing from $PDV; export VERIFY_GATEWAY_CLIENT_ID instead"
  fi
fi

# A trailing slash would produce a double slash in the issuer, and an issuer
# mismatch fails as auth.untrusted_issuer — legible, but not obviously a config
# typo. Normalise instead.
TENANT_URL="${TENANT_URL%/}"

case "$TENANT_URL" in
  https://*) ;;
  http://*) die "VERIFY_TENANT_URL is http://; Verify is HTTPS and the config sets no insecure_http" ;;
  *) die "VERIFY_TENANT_URL must be an absolute https:// URL, got '$TENANT_URL'" ;;
esac

# --- render ---------------------------------------------------------------
# Substitute exactly the two known placeholders, then assert none remain. A
# leftover ${...} would otherwise reach the gateway as a literal string: an
# unresolved client_id passes the non-empty check and fails much later at the
# token endpoint as invalid_client.
render() {
  python3 - "$TMPL" "$TENANT_URL" "$CLIENT_ID" <<'PY'
import re, sys

tmpl_path, tenant_url, client_id = sys.argv[1], sys.argv[2], sys.argv[3]
with open(tmpl_path) as fh:
    text = fh.read()

mapping = {
    "VERIFY_TENANT_URL": tenant_url,
    "VERIFY_GATEWAY_CLIENT_ID": client_id,
}

# Only ${NAME} placeholders, and only the two we know. Anything else is a typo
# or a new variable someone forgot to wire up, and must not pass silently.
unknown = {
    m.group(1)
    for m in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", text)
    if m.group(1) not in mapping
}
if unknown:
    sys.exit("template references unknown variable(s): "
             + ", ".join(sorted(unknown))
             + "\nAdd them to render-verify-config.sh or fix the template.")

for name, value in mapping.items():
    text = text.replace("${" + name + "}", value)

leftover = re.findall(r"\$\{[^}]*\}", text)
if leftover:
    sys.exit("unsubstituted placeholder(s) remain: " + ", ".join(sorted(set(leftover))))

# The generated file must not be edited by hand, and it is gitignored — say both
# at the top, since that is the only place a reader will look.
banner = (
    "# GENERATED FILE — DO NOT EDIT.\n"
    "#\n"
    f"# Rendered from {tmpl_path} by render-verify-config.sh.\n"
    "# Edit the .tmpl and re-run; this file is gitignored and is overwritten on\n"
    "# every Verify run of restart.sh.\n"
    "#\n"
    f"#   tenant     {tenant_url}\n"
    f"#   client_id  {client_id}\n"
    "#\n"
)
sys.stdout.write(banner + text)
PY
}

if [ "$PRINT" = true ]; then
  render
  exit 0
fi

NEW="$(render)" || exit 1

if [ "$CHECK" = true ]; then
  if [ -f "$OUT" ] && [ "$NEW" = "$(cat "$OUT")" ]; then
    echo "  $(green ✓) $OUT is up to date"
    exit 0
  fi
  echo "  $(red ✗) $OUT is missing or stale — run ./render-verify-config.sh" >&2
  exit 1
fi

if [ "$FORCE" = false ] && [ -f "$OUT" ] && [ "$NEW" = "$(cat "$OUT")" ]; then
  echo "  $(green ✓) $OUT $(dim 'already up to date')"
  exit 0
fi

# Warn before clobbering a hand-edited file that predates the template, so the
# edits can be moved into the .tmpl rather than silently lost.
if [ -f "$OUT" ] && ! head -1 "$OUT" | grep -q 'GENERATED FILE'; then
  echo "  $(red '!') $OUT exists and was NOT generated by this script." >&2
  echo "      Overwriting it. If it has hand edits, move them into $TMPL." >&2
fi

printf '%s\n' "$NEW" > "$OUT"
echo "  $(green ✓) rendered $OUT $(dim "(tenant ${TENANT_URL}, client ${CLIENT_ID:0:8}…)")"
