---
name: access-control-testing
description: Broken access control / authorization testing — IDOR and BOLA, function-level authorization (BFLA), horizontal and vertical privilege escalation, forced browsing, mass assignment, and header/path authz bypass (WSTG-ATHZ, OWASP A01 / API1 / API3 / API5, CWE-639/284/285). Use once you can authenticate as one or more users/roles and want to prove one principal can read, modify, or delete another principal's data or reach functions above its privilege; drives multi-identity request replay and response diffing, and emits rupu work units, assets, and findings.
license: Apache-2.0
metadata:
  author: Section9Labs
  wstg: WSTG-ATHZ
  owasp: "A01:2021, API1:2023, API3:2023, API5:2023"
---

# Access Control Testing (IDOR / BOLA / BFLA / Privilege Escalation)

Authorization testing is mostly a **comparison problem**: capture requests as one
identity, replay them as another, and diff the responses. Everything below feeds
that loop. Scanners cannot know who should own what — you (and the matrix script)
can.

Every parse/handoff step below ends in rupu-ingestible output (work-units JSON
array, `assets.mark`, or `findings.report`). Exact JSON shapes: `references/rupu.md`.

## 0. Prerequisites

- Working credentials for **at least two accounts at the same privilege level**
  (user A, user B) and ideally **two privilege levels** (user, admin), plus the
  **unauthenticated** baseline (empty identity).
- An endpoint/object inventory: proxy history (Burp/ZAP/mitmproxy), crawl output
  (katana/gau), or an OpenAPI/GraphQL schema. More captured requests = better matrix.

## 1. Set up identities and capture traffic

1. Log in to each account in a separate browser profile (or Burp session-handling
   rule). Record for each identity the **auth material**: `Cookie` header,
   `Authorization: Bearer ...`, API keys, CSRF tokens. Decode JWTs (`base64 -d` on
   the middle segment) to learn the user id / role claims — those values are your
   object-reference seeds.
2. Walk the full application as the **highest-privilege** identity (admin if you
   have it), exercising every function: profile view/edit, document download,
   order history, admin panels, API calls. Capture everything through a proxy.
   - mitmproxy capture: `mitmdump -w capture.flows "~d example.com & !~u \.(png|css|js|woff2)"`
     then export to the requests JSON the script consumes (see `references/rupu.md`
     for the shape; a small `-s` addon that writes JSON per flow works well).
   - Burp: Proxy history -> select -> save items, or use Autorize live (step 5).
3. Build `identities.json` mapping each identity to its auth headers and a
   numeric privilege rank (`anon=0, user=1, admin=2`).
4. Record each application entry point with `assets.mark` — kind `web:site` at
   depth `mapped`, each captured route as `web:route` at depth `crawled`
   (shapes in `references/rupu.md`).

## 2. IDOR / BOLA — object-level authorization

Enumerate **object references** everywhere, not just the URL path:

- Path segments: `/api/users/1041/orders`, `/invoices/INV-2024-0007.pdf`
- Query params: `?id=`, `?account=`, `?doc=`, `?user_id=`, `?file=`
- JSON bodies: `{"orderId": 884}`, nested ids, arrays of ids
- Headers: `X-User-Id`, `X-Account`, custom tenant headers
- Cookies and hidden form fields; JWT claims (`sub`, `uid`, `tenant`)
- Wrapped ids: base64 (`dXNlcjoxMDQx` -> `user:1041`), hex, md5/sha1 of a
  sequential id, "random" UUIDs that leak elsewhere in responses

Attack procedure per reference:
1. As user A, perform the action on **A's own object** — baseline (status, body).
2. Replay the identical request **substituting B's object id** while still
   authenticated as A. If you get B's data: IDOR (read).
3. Test **every verb** on the same route: `GET` (read), `PUT`/`PATCH` (overwrite
   B's object), `DELETE` (destroy), `POST` (create under B's account). Write/delete
   IDORs are higher impact than reads — confirm the write landed with a follow-up
   GET as B.
4. For numeric ids, increment/decrement and sample a range; for UUIDs, harvest
   other users' GUIDs from responses, exports, search endpoints, and HTML source;
   for wrapped ids, decode -> swap -> re-encode.
5. Try the unauthenticated identity too — some object endpoints skip auth entirely.

Full reference-format catalogue, verb matrix, and ID-harvesting tricks:
`references/idor-bola.md`.

## 3. Function-level authorization (BFLA) and forced browsing

1. Take every **admin-captured** request and replay it with the low-priv user's
   (and the anonymous) auth material. 2xx with the same body = BFLA.
2. **Forced browsing**: directly request admin paths found by content discovery
   (`/admin`, `/manage`, `/api/admin/*`, `/actuator`, `/internal`) as low-priv/anon.
   UI hiding is not access control — the server must reject.
3. Toggle the **method**: a `GET /api/users/7` that is protected may have an
   unprotected `PUT`/`DELETE`; `POST` blocked may pass as `PUT` or with
   `X-HTTP-Method-Override: PUT`. Toggle **content-type**
   (`application/json` <-> `application/x-www-form-urlencoded` <-> `text/xml`) —
   different parsers often sit behind different filters.

Details and discovery wordlists: `references/privilege-and-bypass.md`.

## 4. Privilege escalation and mass assignment

- **Horizontal**: A acts as B (step 2, but on account-scoped *functions*:
  password change, email change, order cancel).
- **Vertical**: user reaches admin function (step 3) or **promotes itself**:
  - Role parameter tampering: resend login/registration/profile responses' role
    fields back in requests: `role=admin`, `group=1`, `access_level=100`.
  - **Mass assignment**: add privileged fields to a profile/update body the UI
    never sends: `{"email":"a@example.com","isAdmin":true}`, `"role":"admin"`,
    `"verified":true`, `"credit":99999`. Discover candidate field names from the
    GET response of the same object, API schemas, JS bundles, and error messages.
    Also try form-encoded (`user[admin]=1` Rails-style) and JSON-in-form variants.
- Confirm escalation by performing an admin-only action afterwards with the
  "promoted" session.

Payload lists: `references/idor-bola.md` (mass assignment section).

## 5. Systematic diffing — the authorization matrix

This is the core method (manual equivalent of Burp **Autorize / AuthMatrix /
Auth Analyzer** — extension workflow in `references/privilege-and-bypass.md`).

Run the scripted replayer over the captured corpus:

```
python3 scripts/authz_matrix.py \
  --requests requests.json --identities identities.json \
  --out matrix.json --work-units wu.json --findings findings.json
```

It replays every request under every identity (auth headers stripped and
replaced, redirects NOT followed), records `status / length / body-sha256` per
cell, and classifies each non-owner cell:

- `CONFIRMED` — 2xx with body hash **identical** to the owner's 2xx baseline:
  cross-identity access proven.
- `CANDIDATE` — 2xx with length within 10% of the owner baseline: likely bypass,
  response differs only by dynamic tokens — eyeball the bodies.
- `REVIEW` — 2xx but substantially different body (could be an error page served
  with 200, or a partial-data leak).
- `ENFORCED` — 401/403/redirect-to-login.

Read the matrix: a **lower-priv identity** scoring CONFIRMED on an admin-owned
request = BFLA/vertical escalation; a **peer identity** scoring CONFIRMED on
another user's object request = IDOR/horizontal. Write verbs upgrade severity.

Handoff (all three rupu outputs, shapes in `references/rupu.md`):
- `wu.json` is a clean work-units array — hand it to the `work-units` skill /
  a `for_each:` fan-out so each flagged cell gets manually confirmed.
- Mark every matrix-tested route `assets.mark` kind `web:route` depth `tested`;
  confirmed ones depth `exploited`.
- `findings.json` holds ready `findings.report` payloads for CONFIRMED cells
  (scope `endpoint`, severity high/critical, WSTG-ATHZ + CWE id, both HTTP
  exchanges in evidence). Review, then record each via the `finding-report` skill.

## 6. Parameter pollution and header/path authz bypass

When a route is ENFORCED, try to bypass the enforcement layer itself
(full list in `references/privilege-and-bypass.md`):

- Override headers: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` (send the
  request to `/` with the real path in the header), `X-Forwarded-For: 127.0.0.1`,
  `X-Forwarded-Host`, `X-Custom-IP-Authorization: 127.0.0.1`.
- Path tricks: trailing `/` (`/admin/`), `/admin/.`, `/./admin`, `/%2e/admin`,
  `/admin%20`, `/admin;/`, `/ADMIN` (case), double URL-encode (`/%2561dmin`),
  `/public/..%2fadmin`.
- **HTTP parameter pollution**: send the authz-checked param twice —
  `?user_id=A_ID&user_id=B_ID` (and reversed); frontend validates one occurrence,
  backend consumes the other. Same in JSON: duplicate keys.
- Verb tricks: `HEAD`, non-standard methods, `X-HTTP-Method-Override`.

Any bypass that reaches the protected function is a finding
(WSTG-ATHZ-02 / CWE-285) — record via `finding-report`, mark the route `exploited`.

## Chaining

**In**: authenticated sessions per identity + request/endpoint inventory (proxy
capture, crawler, API schema).
**Process**: matrix replay (step 5) -> flagged cells -> manual confirmation
(steps 2–4, 6) per work unit.
**Out**: per confirmed cross-account / cross-privilege access, one
`findings.report` (scope `endpoint`, the two request/response exchanges as
evidence, WSTG-ATHZ-02/03/04 or CWE-639/284/285/915); routes marked
`tested`/`exploited` via `assets.mark`. Confirmed admin access or write-IDORs
chain onward: use the gained privilege to expand the capture corpus and re-run
the matrix.
