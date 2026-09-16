#!/usr/bin/env bash
# One-shot restart for the Praxis Policy Engine demo. Useful when:
#   * Keycloak / MCP backend volumes need a clean slate (realm-export
#     changes, token-lifespan edits, drifted state mid-demo).
#   * The gateway's cached JWKS goes stale after a Keycloak restart
#     and validation fails with "InvalidSignature".
#   * You want a known-good state before walking through scenarios.
#
# What it does, in order:
#   1. Kill any local policy gateway listening on :8090.
#   2. docker compose down -v   (wipe Keycloak/MCP volumes).
#   3. docker compose up -d     (fresh containers, realm re-imported).
#   4. Wait for Keycloak's OIDC discovery to respond.
#   5. Run verify-token-exchange.sh as a smoke check.
#   6. Start the gateway in the background; tee its log into
#      ./gateway.log; wait until :8090 is listening.
#   7. Run scenarios/01-bob-allow.sh as an end-to-end smoke check.
#
# Usage (from this directory):
#   ./restart.sh
#   REBUILD_IMAGES=1 ./restart.sh   # force-rebuild container images first
#
# `docker compose up -d` builds any *missing* images (Keycloak + the CIBA
# SPI, auth-channel, hr-mcp) but reuses existing ones. The gateway binary is
# always rebuilt by build-gateway.sh, so Rust changes are picked up either
# way; set REBUILD_IMAGES=1 after editing the SPI (keycloak/ciba-spi/),
# auth-channel, or hr-mcp source so those images are rebuilt too.
#
# Logs:
#   ./gateway.log   — gateway stdout/stderr, follow with `tail -F`.

set -euo pipefail

cd "$(dirname "$0")"

# Which praxis config to run. Defaults to the OPA/Rego PDP (praxis-opa.yaml);
# set GATEWAY_CONFIG=praxis.yaml or praxis-cel.yaml for the Cedar and CEL
# PDP variants, or praxis-verify-opa.yaml for the IBM Verify IdP path.
GATEWAY_CONFIG="${GATEWAY_CONFIG:-praxis-opa.yaml}"

# The Verify path's delegators read their client secret from the environment
# (client_secret_source: {kind: env_var}) rather than from inline YAML, since
# those are live tenant credentials. Source ./.env.verify when present so the
# variable reaches the gateway process below. Gitignored; see
# .env.verify.example.
if [ -f .env.verify ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.verify
  set +a
fi
GATEWAY_LOG="gateway.log"
KEYCLOAK_HOST="${KEYCLOAK_HOST:-http://localhost:8081}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-policy-demo}"
KEYCLOAK_READY_URL="${KEYCLOAK_HOST}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
KEYCLOAK_TIMEOUT="${KEYCLOAK_TIMEOUT:-90}"   # seconds

# Force-rebuild container images (Keycloak+SPI, auth-channel, hr-mcp) before
# starting. Off by default so `up -d` reuses cached images; set to 1 after
# editing image source (e.g. keycloak/ciba-spi/).
REBUILD_IMAGES="${REBUILD_IMAGES:-0}"

# Resolve (and build if needed) the policy gateway binary. Where
# The gateway is built from ./gateway (composes praxis-ai + praxis's policy
# filter) — see build-gateway.sh. Pre-set GATEWAY_BIN to skip the build, or
# GATEWAY_PROFILE=debug for a faster build.
GATEWAY_BIN="${GATEWAY_BIN:-$(./build-gateway.sh)}"
if [ ! -x "$GATEWAY_BIN" ]; then
  echo "fatal: gateway binary not found at '$GATEWAY_BIN'." >&2
  echo "  build-gateway.sh builds ./gateway; see gateway/Cargo.toml." >&2
  exit 1
fi

step() { printf "\n\033[1;34m[restart-demo]\033[0m %s\n" "$*"; }
ok()   { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[1;33m⚠\033[0m %s\n" "$*"; }
die()  { printf "  \033[1;31m✗\033[0m %s\n" "$*"; exit 1; }

# Fail fast on a Verify run with no client secret. Without this the gateway
# starts, identity resolution succeeds, and the first scenario dies at
# delegation.idp_rejected — which reads like a policy problem rather than a
# missing environment variable.
case "$GATEWAY_CONFIG" in
  *verify*)
    if [ -z "${VERIFY_GATEWAY_CLIENT_SECRET:-}" ]; then
      echo "fatal: $GATEWAY_CONFIG needs VERIFY_GATEWAY_CLIENT_SECRET." >&2
      echo "  cp .env.verify.example .env.verify   # then fill in the secret" >&2
      exit 1
    fi
    # policy-verify-opa.yaml is generated from policy-verify-opa.yaml.tmpl: the
    # tenant URL and the exchange client_id are tenant-specific, and Verify
    # GENERATES client ids, so a rebuilt tenant invalidates whatever was
    # committed. Praxis has no env-var indirection for client_id (only for the
    # secret), so substitution happens here, before the gateway reads the file.
    # Rendering is idempotent and quiet when nothing changed.
    step "rendering $GATEWAY_CONFIG's policy config from its template"
    ./render-verify-config.sh || die "could not render policy-verify-opa.yaml"
    ;;
esac

# 1. Kill any existing gateway on :8090.
step "stopping any existing gateway on :8090"
if pids=$(lsof -ti :8090 2>/dev/null); then
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  # Wait up to 5s for the port to free.
  for _ in 1 2 3 4 5; do
    lsof -i :8090 >/dev/null 2>&1 || break
    sleep 1
  done
  if lsof -i :8090 >/dev/null 2>&1; then
    warn "port :8090 still bound — kill -9 fallback"
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
  ok "freed :8090"
else
  ok "no gateway was running"
fi

# 2. docker compose down -v.
step "docker compose down -v (wiping Keycloak + MCP volumes)"
docker compose down -v
ok "containers + volumes removed"

# 3. (optional) rebuild container images, then docker compose up -d.
if [ "$REBUILD_IMAGES" = "1" ]; then
  step "docker compose build (REBUILD_IMAGES=1 — rebuilding Keycloak+SPI, auth-channel, hr-mcp)"
  docker compose build
  ok "images rebuilt"
fi
step "docker compose up -d (fresh start; realm import begins)"
docker compose up -d
ok "containers starting"

# 4. Wait for Keycloak's OIDC discovery endpoint.
step "waiting for Keycloak realm import (timeout ${KEYCLOAK_TIMEOUT}s)"
deadline=$(( $(date +%s) + KEYCLOAK_TIMEOUT ))
while ! curl -fsS "$KEYCLOAK_READY_URL" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    die "Keycloak not ready after ${KEYCLOAK_TIMEOUT}s — check 'docker compose logs keycloak'"
  fi
  printf "."
  sleep 2
done
printf "\n"
ok "Keycloak responding at $KEYCLOAK_READY_URL"

# 4b. Wait for Valkey (the engine's session-store backend). The gateway connects
# lazily on first request, so this is a fail-loud guard rather than a
# hard dependency — a down Valkey would otherwise surface as a denied
# request mid-scenario.
step "waiting for Valkey (session store)"
deadline=$(( $(date +%s) + 30 ))
while [ "$(docker compose exec -T valkey valkey-cli ping 2>/dev/null | tr -d '\r')" != "PONG" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    die "Valkey not ready after 30s — check 'docker compose logs valkey'"
  fi
  printf "."
  sleep 1
done
printf "\n"
ok "Valkey responding (PONG) on localhost:6379"

# 5. verify-token-exchange smoke check (skip on failure but warn loudly).
step "verifying RFC 8693 token-exchange permission"
if ./verify-token-exchange.sh >/dev/null 2>&1; then
  ok "token exchange permission imported correctly"
else
  warn "verify-token-exchange.sh failed — investigate before running scenarios:"
  ./verify-token-exchange.sh || true
fi

# 6. Start the gateway, tee its output to ./gateway.log, wait for :8090.
step "starting gateway (log → $GATEWAY_LOG)"
nohup "$GATEWAY_BIN" -c "$GATEWAY_CONFIG" >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!
disown
# Poll the port for up to 15s.
for _ in $(seq 1 15); do
  if lsof -i :8090 >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    die "gateway exited early — see $GATEWAY_LOG"
  fi
  sleep 1
done
if ! lsof -i :8090 >/dev/null 2>&1; then
  die "gateway didn't bind :8090 within 15s — see $GATEWAY_LOG"
fi
ok "gateway up (pid $GATEWAY_PID, log: $GATEWAY_LOG)"

# 7. End-to-end scenario smoke test.
step "smoke test: scenarios/01-bob-allow.sh"
if out=$(./scenarios/01-bob-allow.sh 2>&1); then
  if echo "$out" | grep -q "HTTP/1.1 200 OK"; then
    ok "Bob's get_compensation returned 200 OK"
  else
    warn "scenario ran but didn't return 200 — output:"
    echo "$out" | tail -10 | sed 's/^/    /'
  fi
else
  warn "scenario script failed — output:"
  echo "$out" | tail -10 | sed 's/^/    /'
fi

step "demo ready"
echo "  gateway log:     tail -F $GATEWAY_LOG"
echo "  chat:            cd agent && python chat.py --persona bob"
echo "  watch backend:   docker compose logs -f hr-mcp"
echo "  stop gateway:    pkill -f 'praxis.*praxis.yaml'"
