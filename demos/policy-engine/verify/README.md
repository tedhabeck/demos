# Verify tenant provisioning

Provisions the demo into an IBM Verify tenant — the four personas and the OAuth
clients that turn their attributes into token claims — using
`keycloak/realm-export.json` as the source of truth.

| File | Purpose |
|---|---|
| `users.csv` | The user source — personas, roles, and the four policy attributes |
| `import-verify-users.sh` | Reads the CSV, defines the custom attributes, creates the users |
| `clients.csv` | The client source — the realm export's four clients, mapped onto Verify |
| `import-verify-clients.sh` | Creates the applications, their grants, and their claim mappers |

Together these automate requirement **R6** ("documented tenant setup") from
`docs/brainstorms/2026-08-31-ibm-verify-idp-requirements.md`. Decision **D5**
kept tenant setup manual; the users, their custom attributes, and the clients'
claim mappers are the parts where doing it by hand reliably costs the most time,
and where a mistake surfaces as a policy deny rather than an error.

## Quick start

```bash
# 1. Inspect what would be sent. Needs no credentials.
./verify/import-verify-users.sh   --dry-run
./verify/import-verify-clients.sh --dry-run

# 2. Add an admin API client to .env.verify (see .env.verify.example)
#    Entitlements: manageUsers + manageAttributes + manageAppAccessAdmin

# 3. See what the tenant actually reports before writing to it
./verify/import-verify-clients.sh --discover

# 4. Provision — users FIRST, and not only for the claim mappers: the clients
#    script grants each persona sign-on access by SCIM id, so the users must
#    exist before the clients are created.
./verify/import-verify-users.sh
./verify/import-verify-clients.sh

# 5. Confirm the claims actually land in a token
./mint-verify-token.sh alice | cut -d. -f2 | base64 -d 2>/dev/null | jq .
./verify-ibm-verify-token-exchange.sh
```

Re-running either script is safe: existing users and clients are reported and
left unchanged rather than overwritten. Use `--delete` then re-run to replace
them.

## Application entitlement

Creating a client is not enough to let it mint. Application access is a separate
resource, and without it every password grant fails:

```
CSIAQ0279E Only entitled users can single sign-on to the application.
```

`import-verify-clients.sh` grants it automatically for `role=mint` clients via
`POST /v1.0/owner/applications/{id}/entitlements`, so there is **no manual
console step**. Two models:

| Flag | Effect |
|---|---|
| *(default)* | Explicit per-user grants for the personas in `users.csv` — only they may sign on |
| `--all-users` | `birthRightAccess: true` — every user in the tenant, the console's "Automatic access for all users and groups" |
| `--no-entitle` | Skip it; the script then reports which clients still need access |

Explicit is the default because it matches how this tenant's `praxis-identity-1`
is already configured, and because the demo's argument rests on four personas
whose differences matter — a client any tenant user can mint from weakens the
eve-vs-bob contrast. Use `--all-users` on a throwaway tenant.

`--discover` prints the current state per application, so you can see who is
entitled before changing anything.

Note this is **invisible in the application object**: `birthRightAccess` reads
back as `null` on `GET /v1.0/applications/{id}` — write-only there, the same trap
as `idTokenSigningAlg` — and the grants live under `/v1.0/owner/...`. Reading an
application back and diffing it against a working one will not reveal it. `GET`
on the owner path does.

## What the scripts do not do

**They do not edit `policy-verify-opa.yaml` directly** — they do not need to.
That file is now *generated* from `policy-verify-opa.yaml.tmpl` by
`render-verify-config.sh`, which substitutes the tenant URL and the exchange
`client_id` from the environment, defaulting to `post_deploy_variables.json`.
`restart.sh` renders it automatically on any `*verify*` config, so the ids that
`import-verify-clients.sh` writes back are picked up with no manual edit.

```bash
./render-verify-config.sh           # render (no-op when up to date)
./render-verify-config.sh --check   # non-zero if stale, for CI
VERIFY_TENANT_URL=https://other.verify.ibm.com ./render-verify-config.sh
```

Why a template rather than an env var in the YAML: Praxis has no env-var
indirection for `client_id`. Only the *secret* does (`client_secret_source:
{kind: env_var}`); `client_id` is a plain `String` read straight into the
outbound Basic auth header, so a literal `${VAR}` there would be sent to Verify
verbatim and fail as `invalid_client` at the token endpoint — well away from the
cause. Substitution therefore has to happen before the gateway reads the file.

The client **secret** is deliberately *not* templated. It stays a runtime lookup
by the gateway, so a live credential never lands in a rendered file on disk.

## Two things worth knowing before editing

**The trailing `""` is load-bearing, and it comes from the CLIENT, not the user
record.** Verify serialises a single-valued custom attribute as a JSON scalar.
Praxis's standard claim mapper reads `roles`/`teams`/`permissions` via
`Value::as_array`, which returns `None` for a string — so a one-role persona gets
an empty `subject.roles`, silently, and `require(role.hr)` then fails as a
*policy deny* rather than a config fault.

Where the pad actually lives, confirmed against the live tenant:

```
stored on the user   roles: ["engineer"]        <- unpadded
minted in the token  roles: ["engineer", ""]    <- padded
```

The padding is injected by each client's CELx claim mapper (`+ ['']` in
`import-verify-clients.sh`), which is why recreating the clients without it
breaks every single-valued persona. `import-verify-users.sh` also appends a pad
to the values it sends; that is belt-and-braces and harmless, but the mapper is
the part that matters. The known cost is that `""` becomes a real set member and
shows up in audit records and `X-Policy-*` output. Remove it — from the mappers
*and* the importer — only after the upstream scalar→single-element-vec fix lands.

**Passwords come from the CSV, not from a rule.** They currently follow
`<username>Lab3151`, matching `post_deploy_variables.json` so
`mint-verify-token.sh` works against a freshly provisioned tenant. The importer
reads the column rather than computing the pattern, because the tenant's actual
passwords are the source of truth — a provisioner that hands you a
non-patterned password would otherwise produce a tenant nobody can log into,
and the failure would surface as a 400 from the ROPC grant, well away from the
cause.

Columns are read **by header name**, so the CSV can be reordered or extended
without touching the script. Multi-valued cells are pipe-separated.

## Attribute slots

Custom attributes must exist in the tenant schema before a user payload may
carry one; an undefined attribute fails the create with a validation error. The
importer claims four of the predefined `customAttribute1..150` slots:

| Attribute | Slot | Read by |
|---|---|---|
| `roles` | `customAttribute1` | `require(role.hr)` — the APL policy gate |
| `permissions` | `customAttribute2` | `perm.view_ssn` redaction, tool gates |
| `teams` | `customAttribute3` | policy context |
| `gh_permissions` | `customAttribute4` | scenario 4's exchange (passthrough claim) |

These numbers are arbitrary but must stay stable — changing one after users
exist orphans the stored values. Note the slots the importer *claims* are not
the slots the owner's tenant actually uses (it was built by hand first):

| Attribute | Importer | This tenant |
|---|---|---|
| `roles` | `customAttribute1` | `customAttribute2` |
| `permissions` | `customAttribute2` | `customAttribute4` |
| `teams` | `customAttribute3` | `customAttribute3` |
| `gh_permissions` | `customAttribute4` | `customAttribute1` |

This is harmless — the attributes already exist, so the importer skips them, and
claim mapping resolves by `scimName` rather than by slot. It only matters if you
provision a *fresh* tenant and then expect the slot numbers to match this one.

**`gh_permissions` has `scimName` `ghpermissions`** — no underscore — on this
tenant. The CELx mappers call `user.getCustomValues("<scimName>")`, so a mapper
written against the display name yields nothing and scenario 4 loses its
permissions claim silently. `import-verify-clients.sh` resolves each scimName
from the tenant rather than assuming; `--discover` prints the mapping.

The realm export's `groups` attribute is deliberately not carried over: it
duplicates `teams` for all four personas and no Verify-path policy reads it.
Add a `groups` column and an `ATTRS` entry if that changes.

## Clients — what the realm export maps onto

The realm export has four clients. Only two are real OAuth clients on Verify:

| Keycloak | Verify | Role |
|---|---|---|
| `hr-copilot` | `praxis-identity-1` | Mints user + client tokens (ROPC + `client_credentials`) |
| `praxis-gateway` | `praxis-sts-1` | Performs the RFC 8693 exchange |
| `github-api` | *(audience string)* | Registered for parity only — see below |
| `workday-api` | *(audience string)* | Registered for parity only — see below |

The two must stay distinct: Verify refuses to let a client exchange its own
tokens (`CSIAQ5207E`), the same split the realm export already has.

`github-api` and `workday-api` are **not clients** on Verify — they are audience
strings in the exchange client's `audiences` list. `clients.csv` registers them
anyway so the console shows the same four names a viewer sees in Keycloak, but
this does **not** make Verify honor a requested `audience` (delta **V1**: Verify
stamps the exchanging client's fixed list and silently accepts unregistered
audiences), and it does **not** reproduce Keycloak's per-audience
`gh-permissions-as-scope` mapper, which is what makes scenario 4's assertion
load-bearing there. Nothing in the demo authenticates as either one. They cannot
be pure placeholders either — Verify rejects an application with every grant type
disabled (`CSIAQ0032`) — so each carries `clientCredentials` and nothing else.
Delete those two rows if you would rather the console show only what
participates; the demo behaves identically.

### Field-level facts, none of them fully documented

Each was confirmed by creating and deleting a throwaway application on the live
tenant. They are the reason this script exists rather than a `curl` snippet.

| Thing | Value | Note |
|---|---|---|
| `templateId` | `998` | **Not** `"0001"`, which circulates in examples. No documented enum; `--discover` reads it off the tenant. |
| JWT tokens | `providers.oidc.token.accessTokenType: "jwt"` | Not `accessTokenFormat`. |
| JWT signing | `providers.oidc.properties.idTokenSigningAlg` | **Required** when `accessTokenType` is `jwt`, despite the name. Omit it and every create fails `CSIAQ0257`. The GET response omits it, so it cannot be discovered by reading an app back. |
| Grant types | `"true"` / `"false"` | Quoted strings, not JSON booleans. |
| Claim mappers | `{ targetName, function: { custom: <CELx> } }` | The API reference describes `JWTAttributeMapBean` as `sourceId` + `targetName`; the working shape is a CELx function calling `user.getCustomValues("<scimName>")`. |
| `sso` | `{ userOptions: "oidc" }` | Required even for a pure OIDC app; satisfies it without inventing a `domainName`. |
| Credentials | Not in the `201` response | It returns only `_links.self.href`; `GET` that to read the generated `clientId` / `clientSecret`. |
| Admin entitlement | `manageAppAccessAdmin` | "Manage application lifecycle". Not `manageApplications`. |
| Sign-on access | `POST /v1.0/owner/applications/{id}/entitlements` | Separate resource, not an application field. `birthRightAccess` for all users, or `additions[]` with a SCIM `subjectId` per user (`grantType: "BRT"`). Needs `manageAppAccessAdmin` or `manageAppAccessOwner`. |
