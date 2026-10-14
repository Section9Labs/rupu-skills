# BOPLA — Broken Object Property Level Authorization (API3:2023)

One flaw, two directions: the API binds client-supplied *properties* it
shouldn't accept (**mass assignment**, CWE-915), or returns properties the
caller shouldn't see (**excessive data exposure**, CWE-213).

---

## Write side: mass assignment (CWE-915)

Frameworks that auto-bind request bodies to models (Rails, Laravel, Spring,
Node ORMs, Django DRF with loose serializers) will persist any property the
model has unless explicitly filtered.

### Setup — build the property dictionary

1. **GET the object** you can write to. Every field in the read response is
   a binding candidate — especially fields the create/update UI never sends:
   `role`, `isAdmin`, `is_verified`, `created_by`, `tenant_id`, `balance`.
2. **Read the spec schema** for the resource. `readOnly: true` fields are the
   *declared* non-writable set — i.e. your target list, because readOnly is
   documentation unless the server enforces it. Response-only schemas
   (`UserFull` vs `UserCreate`) reveal the hidden property names too.
3. **Brute hidden body params** with arjun:
   `arjun -u https://api.example.com/v1/users/1001 -m JSON -oJ arjun.json`
   (add `--headers 'Authorization: Bearer <A>'`; `-m XML`/`-m GET` for other
   encodings). Merge discovered names into the dictionary.
4. Default high-value set: `role`, `roles`, `isAdmin`, `is_admin`, `admin`,
   `is_staff`, `is_superuser`, `is_verified`, `email_verified`, `verified`,
   `account_id`, `tenant_id`, `org_id`, `owner_id`, `user_id`, `balance`,
   `credit`, `credits`, `permissions`, `groups`, `scope`, `plan`, `tier`,
   `price`, `discount`, `total`, `status`, `state`, `approved`, `enabled`,
   `active`, `mfa_enabled`.

### The exact request transformation

Take A's working create/update request and add **one** candidate property
per attempt (one at a time keeps the signal clean; batch only after you know
the server tolerates unknown keys):

```
Baseline: PATCH /v1/users/1001   {"display_name":"Alice"}                     → 200
Test:     PATCH /v1/users/1001   {"display_name":"Alice","role":"admin"}      → ?
Re-read:  GET   /v1/users/1001                                                → "role": ?
```

Try every shape — different binders unwrap different structures:

- **Plain**: `{"role":"admin"}`
- **Nested under the resource key**: `{"user":{"role":"admin"}}` (Rails-style
  strong-params wrapping)
- **Flattened dot-path**: `{"user.role":"admin"}` (some binders expand dots)
- **Prototype pollution form**: `{"__proto__":{"role":"admin"}}` and
  `{"constructor":{"prototype":{"role":"admin"}}}` against Node backends —
  if this persists you likely have more than mass assignment
- **Type juggling** on the value: `"admin"`, `true`, `"true"`, `1`, `[1]`
- **Alternate encodings**: same keys as form-urlencoded
  (`user[role]=admin`) and XML if the endpoint content-negotiates

Also test the **create** path separately from update — `POST /v1/users` with
`"role":"admin"` at signup is the classic. And test *removal* semantics:
`"owner_id": <your id>` on another user's object (BOPLA pivoting into
account takeover).

### Confirming (persistence, then effect)

A 2xx on the write proves nothing — many servers silently drop unknown keys.

1. **Re-read the object** (GET) and check the injected key carries *your*
   value. `scripts/mass_assign.py` does the write → re-read → recursive
   key/value search loop and reports persisted properties.
2. **Check effect**: if `role` persisted, call an admin endpoint with the
   same session (or re-login) — did authorization actually change? If
   `balance`/`price` persisted, complete the business flow at the mutated
   value.
3. Reproduce with a second property or second account to establish the
   pattern (model-wide binding vs one stray field).

### Remediation

Explicit allowlists per operation (DTOs / strong parameters / serializer
`fields=`), never binding the full model from the request; server-side
enforcement of `readOnly`; reject (not ignore) unknown properties where
feasible. CWE-915.

---

## Read side: excessive data exposure (CWE-213)

The server serializes the whole model and relies on the client to filter.

### Procedure

1. **Field diff vs the UI**: for each GET/list response, list every field,
   then list what the client UI actually renders (watch the UI with the
   proxy open). The remainder is the exposure surface. Red flags:
   `password`, `password_hash`, `salt`, `token`, `api_key`, `secret`,
   `reset_code`, `otp_secret`, `ssn`, `dob`, `address`, `phone`, internal
   flags (`is_fraud`, `risk_score`, `internal_notes`), and full embedded
   objects (`"user": {...30 fields...}` where the UI shows a name).
2. **List endpoints first**: `/v1/orders`, `/v1/messages`, search and
   autocomplete endpoints often embed *other users'* full objects per row
   even when the detail endpoint is scoped. Other-user PII in a list = both
   CWE-213 and collection-level BOLA; report the stronger framing.
3. **Response-shaping params that widen output** — append and diff body
   size/fields against baseline:
   `?fields=*`, `?fields=password,role,email`, `?include=user,payment,audit`,
   `?expand=all`, `?view=full`, `?detail=true`, `?debug=1`, `?pretty=1`,
   and the spec/JS-discovered names. GraphQL: request fields the UI never
   selects; run introspection for the full type graph.
4. **Error and alternate formats**: verbose 4xx/5xx bodies, `?format=xml`,
   `Accept: application/xml` — alternate serializers sometimes skip the
   field filter the JSON path has.

### Confirming

Capture the exchange showing the sensitive field with a real (non-null,
non-dummy) value, as the low-privilege identity; for list endpoints, show a
row belonging to another account. One concrete field with real data beats a
long list of nulls.

### Remediation

Per-endpoint response DTOs/serializers with explicit field allowlists;
property-level authorization for role-dependent fields; never return
credentials/secret material in any serialization. CWE-213 (Exposure of
Sensitive Information Due to Incompatible Policies).
