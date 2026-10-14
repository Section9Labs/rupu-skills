# BOLA / IDOR — Broken Object Level Authorization (API1:2023, CWE-639)

The API uses a client-supplied object identifier to fetch/modify data without
verifying the authenticated identity is authorized for *that object*.

## Setup

- Identity A owns a set of objects; identity B is a peer account (same role).
  Optionally LOW (lower role) and ADM (admin) for vertical tests.
- As A, enumerate every object type and record ids + formats:
  `GET /v1/orders` → `[1001, 1004]`; `GET /v1/users/me` → `"id": 1001`;
  create flows return ids in `Location:` headers and response bodies.
- As B, do the same. Now you have known-foreign ids for every object type —
  the strongest test is "B requests A's known id", not blind guessing.

## The exact request transformation

Take A's working request. Change **only** (a) the identity header and (b)
the object identifier. Everything else — content-type, extra headers, body
shape — stays identical so the diff is clean.

```
Baseline (A):   GET /v1/orders/1001        Authorization: Bearer <A>   → 200, A's order
Test 1  (B):    GET /v1/orders/1001        Authorization: Bearer <B>   → ?
Test 2  (B):    GET /v1/orders/1002..1050  Authorization: Bearer <B>   → sweep
Test 3  (none): GET /v1/orders/1001        (no Authorization)          → ?
```

### Identifier classes and how to mutate each

| Format | Example | Mutation |
|---|---|---|
| Sequential int | `/orders/1001` | ±1..±50 sweep; B's known ids; `0`, `1`, very large |
| UUID/GUID | `9f1b...-...` | Harvest only — from list endpoints, embedded refs, exports, emails, websocket frames, HTML source, error messages. Replay harvested foreign UUIDs as B |
| Base64 | `MTAwMQ==` | Decode → mutate inner value → re-encode (watch padding/urlsafe variant) |
| Hashid / short hash | `jR3kq` | Harvest foreign values; if salt is weak, use the hashids algorithm to re-encode integers |
| Hex / Mongo ObjectId | `5f1d7a2e...` | ObjectIds embed a timestamp + counter: increment the trailing counter bytes of a known id |
| Composite | `ORD-2024-1001` | Mutate each segment independently; swap year, sweep counter |

### Where the id lives (test all of them)

- **Path**: the obvious case.
- **Query**: `?order_id=1001`, `?user=1001` — including when the path already
  has `me`/own id (query may win).
- **Body**: `{"account_id": 1001}` in POST/PUT bodies; JSON *and* form
  encodings. Also try **adding** an id field the baseline doesn't send —
  `{"user_id": 1001}` — many frameworks bind it if present.
- **Headers**: `X-User-Id`, `X-Account-Id`, `X-Tenant`, `X-On-Behalf-Of`.
- **Parameter pollution**: `?id=<B's>&id=<A's>` — auth check reads one copy,
  data layer reads the other. Also JSON duplicate keys.
- **Array/batch forms**: `{"ids":[1001,1002]}`, `/orders?ids=1001,1002` —
  batch endpoints often skip per-element checks.

### Nested and indirect references

- `GET /users/me/orders/1002` — parent scoped to self, child id foreign. If
  the route only validates the parent, the child leaks.
- Second-order: as B, create an object referencing A's id
  (`POST /v1/reports {"attachment_id": <A's doc>}`) then read your own
  report back — the server fetched A's attachment on your behalf.
- Export/async paths: request an export/PDF/email of a foreign id — the
  rendering worker often runs with service credentials and no object check.

### Horizontal vs vertical, read vs write

Run the matrix: {B↔A horizontal, LOW→ADM vertical} × {GET read, PUT/PATCH
modify, DELETE destroy}. Write-side BOLA (B PATCHes A's order address, B
DELETEs A's document) is higher impact than read-side; always confirm the
mutation by re-reading as A.

## Automation

`scripts/bola_diff.py` runs the id × identity matrix (owner, each peer,
unauth), printing `status/length/bodyhash` per cell and flagging:

- `CROSS-IDENT 2xx` — non-owner got a success.
- `IDENTICAL-BODY` — non-owner body hash == owner body hash: confirmed same
  object data.
- `UNAUTH 2xx` — no credential needed at all (missing authn, not just authz).

JSON output under `reports/` feeds the finding evidence.

## Confirming

1. Verify the returned data is genuinely A's (unique field values, email,
   order contents) — not an empty 200, not a public/shared object.
2. Reproduce on a **second object id** and ideally in the reverse direction
   (A reads B's object).
3. For writes, show before/after state as the victim identity.

## Remediation (for the report)

Enforce object-level authorization in a single server-side layer: resolve
ownership/tenancy from the session, not from client input; use per-request
policy checks (e.g. `object.owner_id == session.user_id` or a centralized
policy engine) on every data access, including batch, nested, export, and
background paths. Prefer unpredictable ids only as defense-in-depth, never
as the control. CWE-639 (Authorization Bypass Through User-Controlled Key).
