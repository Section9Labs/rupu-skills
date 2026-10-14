# BFLA — Broken Function Level Authorization (API5:2023, CWE-285)

The API exposes privileged *functions* (admin operations, management
endpoints, destructive verbs) without verifying the caller's role. Object
ownership may be checked while the function-level role check is missing — or
vice versa.

## Setup

- LOW (or B): the low-privilege identity you attack *as*.
- ADM: an admin identity, if available, to (a) enumerate the real admin
  surface and (b) know what a legitimate 200 looks like so you can tell a
  real bypass from a decoy page.
- Build the privileged-function list from: discovery output
  (kiterunner/ffuf hits on `admin`, `manage`, `internal`), the OpenAPI spec
  (every operation tagged admin or absent from the user UI), JS bundles
  (grep for `"/admin`, `role ===`, `isAdmin`), and ADM's own captured
  traffic.

## The exact request transformation

Take a privileged request (captured from ADM, or constructed from the spec)
and swap **only the identity** to LOW:

```
Baseline (ADM): GET /v1/admin/users          Authorization: Bearer <ADM> → 200, user list
Test (LOW):     GET /v1/admin/users          Authorization: Bearer <LOW> → ?
Test (none):    GET /v1/admin/users          (no Authorization)          → ?
```

If you have no ADM traffic, construct requests from the spec's schema and
send them as LOW; a 400 validation error (not 401/403) already proves the
role check ran *after* parsing — keep fixing the body until you get through.

### Target classes

1. **Admin route trees**: `/admin/*`, `/api/admin/*`, `/v1/admin/*`,
   `/manage/*`, `/management/*`, `/internal/*`, `/_internal/*`,
   `/superuser/*`. Also version-skew: `/v1/admin/*` may be locked while
   `/v2/admin/*` or `/api/admin/*` (no version) is not.
2. **Framework/management endpoints**: Spring `/actuator/*` (`/actuator/env`,
   `/actuator/heapdump`, `/actuator/loggers`), `/metrics`, `/debug/pprof/*`,
   `/console`, `/graphql` introspection, `/swagger-ui`, `/health` with
   detail params.
3. **Spec-only / non-UI operations**: bulk export, user listing,
   impersonation (`POST /v1/auth/impersonate`), feature toggles, invite/role
   management, refunds. If the UI never calls it, odds are nobody wired the
   role check.
4. **Method tampering on known objects**: for a resource LOW can GET, swap
   the verb:
   - `GET /v1/users/1002` → `DELETE /v1/users/1002`, `PUT`, `PATCH`.
   - `GET /v1/orders/1001` → `POST /v1/orders/1001/refund`.
   Routers and gateways frequently authorize per-path with the method
   ignored. Also probe `OPTIONS` first — the `Allow:` header enumerates
   verbs the route actually accepts.
5. **Method override smuggling** (bypasses proxy/gateway ACLs that filter
   literal verbs):
   - Headers on a `POST`: `X-HTTP-Method-Override: DELETE`,
     `X-HTTP-Method: DELETE`, `X-Method-Override: DELETE`.
   - Param: `POST /v1/users/1002?_method=DELETE` or `_method=DELETE` in a
     form body (Rails/Laravel/Express method-override conventions).
6. **BFLA × BOLA combo**: privileged function + foreign object id —
   `POST /admin/users/1002/reset-password` as LOW. Test this for every
   admin operation that takes an object id; it is the highest-impact shape.

## Reading results

- `401` → not authenticated (check the token is attached). `403` → check
  present and working. `404` on a route ADM gets `200` on → route-level
  hiding, try case variants, trailing slash, `%2e` tricks, alternate
  versions.
- `200` means nothing until you confirm **effect**: after
  `DELETE /v1/users/1002`, GET the user — gone/disabled? After a role
  change, does the target token now carry the new role?
- A `400` schema error as LOW on an admin route = the authz check is
  missing; iterate the body until the operation executes.
- Diff LOW's response against ADM's: identical body = full bypass; trimmed
  body = partial (still report, lower impact).

## Confirming

Demonstrate one concrete privileged state change (or privileged read with
real data) as LOW, verified from a second vantage (ADM view, or the victim
account). Capture both the LOW request/response and the verification
exchange.

## Remediation (for the report)

Deny-by-default function-level authorization in middleware applied to every
route and method — including overrides, all API versions, and non-UI
operations. Role checks must bind to the session's server-side role, and
method-override headers/params should be disabled at the gateway. CWE-285
(Improper Authorization).
