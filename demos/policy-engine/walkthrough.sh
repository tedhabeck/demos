#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Praxis Contributors
#
# Narrated end-to-end walkthrough of every demo feature. Fires the
# 7 scenario scripts in sequence with explanatory text between each,
# so a live audience can see:
#
#   * the actual HTTP request the gateway received
#   * what the gateway responded with (success result vs MCP JSON-RPC
#     error envelope vs HTTP 401)
#   * which violation code (if any) the gateway emitted
#
# Pairs well with a second terminal running:
#
#     docker compose logs -f hr-mcp
#
# so the audience can see (or NOT see) the request reaching the
# backend — and the audit-log JSON the gateway emits on its stderr.
#
# Usage:
#
#     ./walkthrough.sh            # narrated, pause for input between scenarios
#     ./walkthrough.sh --fast     # no pauses — for smoke-testing
#
# Assumes the stack is already up: `docker compose up -d` and the
# gateway is running on :8090. Run `./verify-token-exchange.sh` first
# if you want to double-check Keycloak.

set -euo pipefail

FAST="${1:-}"

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEMO_DIR"

bold()  { printf '\033[1m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }
cyan()  { printf '\033[36m%s\033[0m' "$*"; }

banner() {
  echo
  echo "$(cyan ════════════════════════════════════════════════════════════)"
  echo "$(cyan "  $*")"
  echo "$(cyan ════════════════════════════════════════════════════════════)"
}

beat() {
  echo
  echo "  $(yellow ▸) $*"
}

pause() {
  if [ "$FAST" = "--fast" ]; then
    return
  fi
  echo
  echo "  $(dim "[press enter to continue, q to quit]")"
  read -r ans
  if [ "${ans:-}" = "q" ] || [ "${ans:-}" = "quit" ]; then
    echo "  $(dim bye)"
    exit 0
  fi
}

# ----- Pre-flight ---------------------------------------------------------

banner "Pre-flight"

beat "Is the gateway listening on :8090?"
if ! curl -fsS --max-time 2 -o /dev/null -X POST http://localhost:8090/mcp \
    -H "Content-Type: application/json" -d '{}' 2>/dev/null; then
  if ! lsof -nP -iTCP:8090 -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
    echo "  $(yellow ✗) gateway is not listening on :8090"
    echo "  $(dim "from this directory: ./restart.sh   (builds praxis if needed, then starts it)")"
    exit 1
  fi
fi
echo "  $(green ✓) gateway up"

if [ "${USE_VERIFY:-}" = "true" ]; then
  beat "Can IBM Verify mint and exchange a token?"
  if ! ./verify-ibm-verify-token-exchange.sh >/dev/null 2>&1; then
    echo "  $(yellow ✗) verify-ibm-verify-token-exchange.sh failed"
    echo "  $(dim "check the tenant is reachable and post_deploy_variables.json is populated")"
    exit 1
  fi
  echo "  $(green ✓) IBM Verify RFC 8693 token exchange works"

  # USE_VERIFY switches only which IdP the scenarios MINT from. If the running
  # gateway is still on a Keycloak config it rejects every Verify token at
  # identity.resolve and all 7 scenarios fail with auth.untrusted_issuer — which
  # reads like a policy problem. Probe it directly: send a real Verify-minted
  # token through the gateway and look at which violation (if any) comes back.
  beat "Is the running gateway configured for Verify?"
  _probe=$(USE_VERIFY=true bash scenarios/01-bob-allow.sh 2>&1 || true)
  case "$_probe" in
    *auth.untrusted_issuer*)
      echo "  $(yellow ✗) the gateway does not trust the Verify issuer"
      echo "  $(dim "USE_VERIFY switches token minting only — the gateway needs its own config:")"
      echo "  $(dim "USE_VERIFY=true GATEWAY_CONFIG=praxis-verify-opa.yaml ./restart.sh")"
      exit 1
      ;;
    *delegation.idp_rejected*)
      echo "  $(yellow ✗) the gateway trusts Verify but exchanges tokens elsewhere"
      echo "  $(dim "a Keycloak delegator cannot exchange a Verify-minted token:")"
      echo "  $(dim "USE_VERIFY=true GATEWAY_CONFIG=praxis-verify-opa.yaml ./restart.sh")"
      exit 1
      ;;
  esac
  echo "  $(green ✓) gateway is on the Verify path"
else
  beat "Can Keycloak mint a token?"
  if ! ./verify-token-exchange.sh >/dev/null 2>&1; then
    echo "  $(yellow ✗) verify-token-exchange.sh failed"
    echo "  $(dim "try: docker compose down -v && docker compose up -d")"
    exit 1
  fi
  echo "  $(green ✓) Keycloak STE v2 works"
fi

beat "Tip — open a second terminal and run:"
echo "      $(dim "docker compose logs -f hr-mcp")"
echo "    you'll see what reaches the backend (or doesn't)."
pause

# ----- WORKDAY FLOW (Pattern 1) -------------------------------------------

banner "WORKDAY FLOW — single-IdP perms on the user token"

beat "Scenario 1 — Bob (HR + view_ssn) asks for compensation."
beat "Expected: HTTP 200 + full record including the SSN."
beat "Backend (hr-mcp) sees: the IdP-minted workday-api token (NOT bob's user JWT)"
beat "                       AND the SSN value as bob sent it (no redact, he has view_ssn)."
pause
bash scenarios/01-bob-allow.sh
pause

beat "Scenario 2 — Alice (engineer, NOT HR) asks for the same."
beat "Expected: HTTP 200 + JSON-RPC error envelope, code -32001."
beat "          data.violation = routes.tool:get_compensation.apl.policy[0]"
beat "Why HTTP 200 + JSON-RPC error (not HTTP 403)? Per MCP's Tools spec,"
beat "gateway-side denials are reported as JSON-RPC errors so MCP clients"
beat "can correlate the failure to the original request id."
beat "Backend: NEVER sees the request — gateway short-circuits at the APL gate."
beat "Keycloak: NEVER sees a token-exchange call (delegate() runs AFTER policy)."
pause
bash scenarios/02-alice-deny.sh
pause

beat "Scenario 3 — Eve (HR but NO view_ssn) asks for compensation, include_ssn=true."
beat "Expected: HTTP 200 + success. Two redacts fire — one on the request, one on the response:"
beat "  • args.ssn → [REDACTED] before the request reached the backend."
beat "    Watch hr-mcp logs: body.params.arguments will show ssn=[REDACTED]."
beat "  • result.ssn → [REDACTED] in the client's JSON response body."
beat "    Eve sees ssn=[REDACTED] even though hr-mcp actually returned Jane's"
beat "    real SSN — the gateway rewrote it on the way back."
beat ""
beat "Caveat (full disclosure): the body-rewrite uses a 'pad with trailing"
beat "spaces' workaround today because praxis doesn't expose Content-Length"
beat "recompute from on_request_body. Documented as a known upstream issue in"
beat "docs/upstream-issues/01-content-length-on-body-rewrite.md. The redact"
beat "logic itself is real — the wire-format trick is a workaround."
pause
bash scenarios/03-eve-redact.sh
pause

# ----- GITHUB FLOW (Pattern 3 — Cedar PDP) -------------------------------

banner "GITHUB FLOW — Cedar PDP + per-audience IdP claim mapping"

beat "Scenario 4 — Alice (engineering) searches internal repos."
beat "Expected: HTTP 200 + success."
beat "Layer 1: APL gate require(team.engineering | team.security) → PASS"
beat "Layer 2: Cedar policy engineering-internal-repos → PERMIT"
beat "Layer 3: Token exchange to github-api audience → succeeds"
beat "Layer 4: delegation.granted.permissions contains repo:read:internal → PASS"
pause
bash scenarios/04-alice-internal-allow.sh
pause

beat "Scenario 5 — Alice (engineering) searches EXTERNAL repos."
beat "Expected: HTTP 200 + JSON-RPC error, data.violation=cedar.default_deny."
beat "Cedar's engineer policy when-clause requires visibility==internal."
beat "External fails the when-clause → no permit fires → default deny."
beat "No IdP call happens. GitHub never sees the request."
pause
bash scenarios/05-alice-external-cedar-deny.sh
pause

beat "Scenario 6 — Bob (HR) tries to search ANY repos."
beat "Expected: HTTP 200 + JSON-RPC error at the APL gate."
beat "Fast-path deny: cheap predicate (require team.engineering | team.security)"
beat "runs first. Bob is team.hr, neither matches. Cedar never runs."
pause
bash scenarios/06-bob-apl-deny.sh
pause

# ----- PLUGIN FLOW (PII scanner + audit logger) --------------------------

banner "PLUGIN FLOW — validator + observation plugins"

beat "Scenario 7 — Bob tries to send_email with an SSN in the body."
beat "Expected: HTTP 200 + JSON-RPC error, data.violation=pii.detected."
beat "APL gate require(perm.email_send) PASSES (Bob has the perm)."
beat "The pii-scan plugin walks args.body, hits the SSN regex pattern, denies."
beat "audit-log is ordered ahead of pii-scan, so it fires first — observation-"
beat "only, can't block — and records the attempt before the deny short-circuits."
beat "The scenario prints that emitted audit record inline below the response."
pause
bash scenarios/07-bob-pii-deny.sh

# ----- Wrap up ------------------------------------------------------------

banner "Walkthrough complete"

beat "Recap of what the gateway demonstrated:"
echo "      $(dim "•") identity from JWT (jwt-user reads X-User-Token,"
echo "        jwt-client reads Authorization — both validated against"
echo "        $(if [ "${USE_VERIFY:-}" = "true" ]; then printf "IBM Verify's"; else printf "Keycloak's"; fi) live JWKS)"
echo "      $(dim "•") attribute-based APL policy (require(team.X), role.Y,"
echo "        perm.Z) with fast-path deny semantics"
echo "      $(dim "•") Cedar PDP for relationship-based authorization"
echo "        (principal × resource attributes), with \${args.X}"
echo "        substitution into the resource block"
if [ "${USE_VERIFY:-}" = "true" ]; then
  # Deliberately weaker wording than the Keycloak line. Verify stamps the
  # exchanging client's whole registered resource list on every token rather
  # than honoring the requested audience (delta V1), so "per-audience minted
  # tokens" would be false here.
  echo "      $(dim "•") RFC 8693 OAuth token exchange against IBM Verify —"
  echo "        exchanged tokens (see the V1/V2 deltas below)"
else
  echo "      $(dim "•") RFC 8693 OAuth token exchange against real Keycloak"
  echo "        v2 Standard Token Exchange — per-audience minted tokens"
fi
echo "      $(dim "•") on-the-wire body rewriting (redact) — the tool"
echo "        literally never sees the redacted field"
echo "      $(dim "•") field-level plugin (PII scanner) catching content"
echo "        BEFORE it reaches the backend"
echo "      $(dim "•") audit observation plugin — emits a structured record at"
echo "        its point in each route's chain (after delegation on allow"
echo "        paths; ahead of the PII gate on send_email, so denied"
echo "        attempts land on the trail too)"
echo "      $(dim "•") MCP-compliant error responses: JSON-RPC error envelope"
echo "        for application denials (HTTP 200, code -32001), HTTP 401 +"
echo "        WWW-Authenticate for transport-level auth failures."
echo
if [ "${USE_VERIFY:-}" = "true" ]; then
  beat "$(bold "Ran against IBM Verify") — the same APL policy text, a different IdP."
  echo "      $(dim "diff policy-opa.yaml policy-verify-opa.yaml — every difference is in")"
  echo "      $(dim "the identity and delegation blocks. Routes, PDP, redaction, PII scan,")"
  echo "      $(dim "taint and audit are byte-identical. That diff is the argument.")"
  echo
  beat "Two things this path does NOT demonstrate (be straight about these):"
  echo "      $(dim "•") V1 — Verify stamps the exchanging client's full registered"
  echo "        resource list on every token regardless of the requested"
  echo "        audience, and accepts an unregistered one silently. Say"
  echo "        \"exchanged token,\" not \"audience-scoped token.\""
  echo "      $(dim "•") V2 — layer 4 is an echo, not an entitlement check. Verify"
  echo "        returns whatever scope was requested, so scenario 4's assertion"
  echo "        verifies wire-shape parity, not an authorization decision. On"
  echo "        Keycloak the same assertion IS load-bearing."
  echo
  beat "Also Keycloak-only: scenarios 8-12, and CIBA approval (10-11)."
  echo "      $(dim "the tenant's clients cannot use the CIBA grant (CSIAQ5303E) and")"
  echo "      $(dim "Verify tokens carry no manager claim. walkthrough.sh runs 1-7.")"
  echo
fi
beat "To try this through an LLM, start chat.py:"
echo "      $(dim "cd agent && python chat.py --persona bob   # or use --model")"
echo
