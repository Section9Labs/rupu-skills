---
name: api-authorization
description: Multi-identity differential testing of API authorization — BOLA/IDOR (API1:2023), BFLA (API5:2023), and BOPLA mass-assignment/excessive-data-exposure (API3:2023). Use in phase 4 of an API engagement, after endpoint discovery, when you hold at least two authenticated identities and want to find cross-tenant object access, privileged function access, and writable privileged properties.
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# API Authorization Testing (BOLA / BFLA / BOPLA)

Authorization flaws are the highest-yield class in API testing. The entire
discipline is one technique applied three ways: **multi-identity differential
testing** — take a request that works for identity A, replay it as identity B
(and unauthenticated) with the object/function/property changed, and **diff
status, body, and size**. Same request + different identity + data that should
be forbidden = finding.

This skill is phase 4 of the `api-testing` flow. It consumes the per-endpoint
work units in `reports/api-units.json` produced during discovery (see
`references/rupu.md`), tests each endpoint, and emits findings and coverage.

## 1. Test setup

You need identities before anything else:

1. **Two accounts of the same role** — A and B (self-register if the API has
   signup; otherwise ask the operator for provisioned creds). These drive
   horizontal tests.
2. Where possible, **one lower-priv** account and **one admin** account. These
   drive vertical BFLA tests and give you ground truth on what admin responses
   look like.
3. Capture each identity's credential exactly as the API consumes it: the full
   `Authorization: Bearer <jwt>` header, `Cookie: session=...`, API key header
   (`X-API-Key: ...`), or whatever the traffic shows. Store them verbatim —
   the scripts below take raw header strings.
4. **Inventory A's objects.** As A, exercise every create/list endpoint and
   record each object id A owns: order ids, user id, document ids, message
   ids, team/org ids. Note the id *format* (sequential integer, UUID, base64,
   hashid, composite like `ORD-2024-1001`). This list is your BOLA ammunition.
5. Decode A's and B's JWTs (`base64 -d` on the middle segment) and note the
   claims: `sub`, `role`, `tenant_id`, `scope`. These tell you which claims
   the server *might* be trusting and which properties to target in BOPLA.

Keep a scratch file per identity:

```
# identities.txt
A    Authorization: Bearer eyJhbGciOi...A
B    Authorization: Bearer eyJhbGciOi...B
LOW  Authorization: Bearer eyJhbGciOi...low
ADM  Authorization: Bearer eyJhbGciOi...admin
```

## 2. The core loop (applies to every test below)

For each endpoint under test:

1. Capture A's **known-good request** (method, path, params, body) and A's
   response — this is the baseline.
2. Replay it as **B**, as **LOW**, and with **no auth**, changing only the
   identity header (and, for BOLA, the object id).
3. Diff: HTTP status, Content-Length, body hash, and the actual fields.
   - Identical 200 body across identities on an owner-scoped object → BOLA.
   - 200 for LOW on an admin function → BFLA.
   - Injected property visible on re-read → BOPLA write.
4. **Confirm on a second object / second account pair before reporting.** One
   hit can be a shared/public object; two independent hits is a pattern.
5. Record coverage and findings per `references/rupu.md` — endpoint goes to
   `tested` once probed, `exploited` when cross-identity impact is confirmed,
   and every confirmed issue is a `findings.report` with both identities'
   HTTP exchanges as evidence.

## 3. BOLA / IDOR (API1:2023, CWE-639)

Full procedure and transformation catalog: `references/bola.md`.

Swap object identifiers across accounts, everywhere an id appears:

- **Path ids**: `GET /v1/orders/1001` → `/v1/orders/1002` (B's id, or sweep
  ±50 around A's ids for sequential schemes).
- **UUID/GUIDs**: never brute-force blind. Harvest other users' UUIDs from
  list endpoints, embedded objects, export files, websocket frames, emails,
  and error messages — then replay them as the wrong identity.
- **Encoded ids**: base64 (`MTAwMQ==` → decode, increment, re-encode),
  hashids, hex. Decode, mutate, re-encode.
- **Composite ids**: `ORD-2024-1001` — mutate each segment independently.
- **Ids in body/query/header**: `{"account_id": 1001}` in POST bodies,
  `?user_id=`, `X-User-Id:`, and ids inside JWT-adjacent headers. Path auth
  is often enforced while body/header ids are trusted raw.
- **Nested / indirect references**: `/users/me/orders/1001` — swap the child
  id while the parent stays `me`. Also second-order: create an object as B
  that *references* A's id (`{"attachment_id": <A's>}`) and read it back.
- Test both **horizontal** (B ↔ A, same role) and **vertical** (LOW reads
  admin-owned objects) directions, and all verbs — read BOLA (GET), write
  BOLA (PUT/PATCH), delete BOLA (DELETE).

Automate the sweep with the helper:

```
python3 scripts/bola_diff.py \
  --url 'https://api.example.com/v1/orders/{ID}' \
  --method GET \
  --ids ids-orders.txt \
  --identity A 'Authorization: Bearer eyJ...A' \
  --identity B 'Authorization: Bearer eyJ...B' \
  --owner A \
  --out reports/bola-orders.json
```

`{ID}` is substituted into URL, body, and headers. The script replays every
id as every identity **plus unauthenticated**, prints a `status/length/hash`
matrix, and flags: non-owner 2xx (candidate), non-owner 2xx with the *same
body hash as the owner* (confirmed identical data), and unauth 2xx (missing
authentication entirely). The JSON written to `reports/` is the normalized
record for the finding evidence.

**Signal reading**: a 200 to B containing A's data is BOLA. A 200 with an
*empty* result set is correct per-user filtering, not a finding. 403/404 to B
is correct. A 500 means the check crashed — probe adjacent ids. For write
verbs, confirm by re-reading the object as A: did B's PATCH actually change
A's data?

## 4. BFLA (API5:2023, CWE-285)

Full procedure: `references/bfla.md`. Target privileged *functions*, not
objects:

- **Admin surfaces**: as LOW/B, call every `/admin/*`, `/manage/*`,
  `/internal/*` route found in discovery, the spec, or JS bundles — plus
  framework management endpoints (`/actuator/*`, `/metrics`, `/debug`,
  `/console`, `/_internal`). Compare against ADM's responses to know what a
  real 200 looks like.
- **Spec-only operations**: operations in the OpenAPI document that the UI
  never calls (bulk export, user listing, impersonation, feature toggles)
  frequently have no function-level check because "no one calls them".
- **Method tampering**: on an object the user can legitimately GET, swap the
  verb — `GET /v1/users/1002` → `DELETE /v1/users/1002`, `PUT`, `PATCH`.
  Routers often authorize per-path, not per-method.
- **Method override headers**: send `POST` with `X-HTTP-Method-Override:
  DELETE` (also `X-HTTP-Method`, `X-Method-Override`, and `_method=DELETE`
  as a form/query param) to slip a privileged verb past a proxy ACL that
  only filters literal methods.
- **Mixed BOLA+BFLA**: LOW calling `POST /admin/users/1002/reset-password`
  — a privileged function *on another user's object* is the highest-impact
  combination; test it whenever an admin function takes an object id.

Confirm by effect, not status: a 200 on `DELETE /v1/users/1002` means
nothing until a follow-up GET shows the user is gone (or disabled).

## 5. BOPLA (API3:2023)

Full procedure: `references/bopla.md`. Two sides of one flaw — the API binds
or exposes object *properties* without a per-property check.

### 5a. Mass assignment (write side, CWE-915)

1. **Discover property names**: diff a GET of the object against the fields
   the create/update UI sends; read the spec's full schema (writeOnly/
   readOnly markers are hints, not enforcement); run `arjun -u <url> -m JSON`
   to brute hidden body parameters.
2. **Inject** candidate privileged properties into create/update bodies, one
   at a time: `role`, `isAdmin`, `is_admin`, `admin`, `is_verified`,
   `email_verified`, `account_id`, `tenant_id`, `owner_id`, `balance`,
   `credit`, `permissions`, `groups`, `price`, `discount`, `status`, `plan`.
3. Try all shapes: plain (`"role":"admin"`), nested under the resource key
   (`"user":{"role":"admin"}`), flattened (`"user.role":"admin"`), and
   prototype pollution form (`"__proto__":{"role":"admin"}`) against Node
   backends.
4. **Check persistence by re-reading the object** with GET — a 200 on the
   write means nothing; the property must come back with your value. Then
   check *effect*: does the session now act as admin?

Automate:

```
python3 scripts/mass_assign.py \
  --url 'https://api.example.com/v1/users/1001' \
  --method PATCH \
  --body base-user.json \
  --read-url 'https://api.example.com/v1/users/1001' \
  --header 'Authorization: Bearer eyJ...A' \
  --props role=admin isAdmin=true balance=9999 account_id=1 \
  --variants plain,flat,proto --nest-key user \
  --out reports/massassign-users.json
```

The script sends each injected body, re-reads the object, recursively
searches the read response for the injected key/value, and reports which
properties **persisted** — those are the findings. For POST-create flows,
`--id-field id` extracts the new object's id from the create response and
substitutes it into `{ID}` in `--read-url`.

### 5b. Excessive data exposure (read side, CWE-213)

- Diff every GET/list response against what the client UI actually renders.
  Extra fields the UI drops are the finding surface: `password`, `*_hash`,
  `salt`, `ssn`, `token`, `api_key`, `reset_code`, `otp_secret`, internal
  flags (`is_fraud`, `internal_notes`), and full embedded user objects.
- **List endpoints** are the worst offenders: `/v1/orders` returning every
  order's full buyer object leaks other users' PII even when `/orders/{id}`
  is correctly scoped.
- Probe response-shaping params that *widen* output: `?fields=*`,
  `?fields=password,role`, `?include=user,payment`, `?expand=all`,
  `?view=full`, `?debug=1`, and GraphQL-style field selection. Compare body
  size with and without.
- Cross-check with BOLA: a list endpoint that returns all tenants' rows is
  BOLA at collection level; report it as such.

## 6. Reading results and reporting

The diff is the signal. Before reporting, every finding needs:

- The **same request as two identities** with divergent authorization
  outcome (A's legit exchange + B's forbidden-but-successful exchange), or
  the write + re-read pair for mass assignment.
- Confirmation on a **second object** (BOLA) or second property/account
  (BOPLA/BFLA) so you're reporting a pattern, not a shared resource.
- Concrete impact statement: whose data, what action, what escalation.

Then wire it into rupu — `assets.mark` depth updates and `findings.report`
with `http_exchange` evidence for both identities, pinned to the
`api:endpoint` by its `http_route` coordinate. For the mechanics, import the
reporting pack's skills by name and do not re-implement them:

- **`work-units`** — splits inputs into fan-out units (`split.py openapi`
  for a Swagger/OpenAPI document, per resource). This skill's scripts emit
  the normalized JSON under `reports/` that `work-units` or a `for_each`
  fan-out consumes.
- **`coverage-assets`** — the `assets.mark` wiring for `api:service` /
  `api:endpoint` coverage.
- **`finding-report`** — the full `findings.report` finding contract.

`references/rupu.md` has the exact asset shapes, the
`read_file`+`for_each` / `dispatch` fan-out over `reports/api-units.json`,
and the evidence format.
