# rupu wiring for auth-session-testing

Every parse/handoff step in SKILL.md ends by producing one of three rupu-ingestible
outputs: a **work-units JSON array**, **`assets.mark`** calls, or a
**`findings.report`** call. This file gives the exact shapes.

## 1. Work units (fan-out)

Write a file whose FIRST character is `[` — a clean JSON array, one object per unit.
rupu's `for_each:` JSON-parses such a file (read via the `read_file` tool); a lead
agent reads the same file and `dispatch`es one child per element. Normalize/split
large arrays with the shared `work-units` skill before dispatch.

Unit shape used throughout this skill:

```json
[
  {
    "id": "auth-login-brute-example.com",
    "title": "Brute-force login at https://example.com/login",
    "targets": ["https://example.com/login"],
    "hints": {
      "mechanism": "login-form",
      "method": "POST",
      "params": "user,pass",
      "failure_string": "Invalid username or password",
      "valid_users": "admin,jsmith"
    }
  },
  {
    "id": "auth-jwt-hmac-crack-example.com",
    "title": "Crack HMAC secret of session JWT",
    "targets": ["https://example.com/api/me"],
    "hints": {
      "mechanism": "jwt",
      "attack": "hmac-crack",
      "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
      "alg": "HS256"
    }
  }
]
```

Rules:
- `id` unique and stable (mechanism + attack + host).
- `targets` is a list of URLs the child should hit.
- `hints` values are strings; carry everything the child needs to start without
  re-discovery (failure strings, tokens, usernames, cookie names).
- Both scripts emit this shape: `analyze_jwt.py --work-units out.json` (one unit per
  JWT attack worth attempting) and `session_audit.py --work-units out.json` (one unit
  per cookie/session weakness to confirm).
- Valid credentials / forged tokens destined for the authorization track go out as
  units with `hints.credentials` / `hints.token`.

## 2. Assets (`assets.mark`, web profile)

Kinds are profile-namespaced — prefix `web:`.

Site (first contact with an origin):

```json
{
  "kind": "web:site",
  "label": "https://example.com",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "depth": "mapped"
}
```

Route (every auth endpoint you find; include `param` when a parameter matters):

```json
{
  "kind": "web:route",
  "label": "POST /login (user,pass)",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/login"},
    {"t": "param", "v": "pass"}
  ],
  "depth": "crawled"
}
```

Depth ladder — mark the rung actually reached:
- `mapped`   — origin probed / known to exist (§0 initial sweep).
- `crawled`  — route discovered by walking the app (§0 auth-surface map).
- `tested`   — route fuzzed or vuln-tested (hydra/ffuf run, jwt_tool playbook run,
  session audit executed) even if nothing confirmed.
- `exploited` — weakness confirmed: creds cracked, bypass worked, forged JWT
  accepted, fixation demonstrated, CSRF PoC fired.

Re-mark with the higher rung as you progress; never leave a cracked login at `tested`.

## 3. Findings (`findings.report`)

Use scope `endpoint` with `target_ref` = the affected URL for route-level issues;
scope `host` only for host-wide issues (missing HSTS, global cookie policy).
`severity` ∈ info|low|medium|high|critical.

The `web` profile completeness checks require ALL THREE of:
1. finding pinned to a route/url (`target_ref`),
2. an HTTP request/response exchange inside `evidence`,
3. an OWASP (WSTG id or Top-10) or CWE classification.

Template (this is what `session_audit.py --findings` pre-fills):

```json
{
  "title": "Session cookie issued without HttpOnly or Secure",
  "scope": "endpoint",
  "target_ref": "https://example.com/login",
  "severity": "medium",
  "classification": {"owasp": "WSTG-SESS-02", "cwe": "CWE-614"},
  "evidence": {
    "rationale": "The session cookie is readable by script (no HttpOnly, CWE-1004) and transmittable over cleartext (no Secure, CWE-614), so any XSS or on-path position yields session hijack. Evidence: the Set-Cookie header issued at login.",
    "http_exchange": "POST /login HTTP/1.1\nHost: example.com\n...\n\nHTTP/1.1 302 Found\nSet-Cookie: SESSIONID=abc123; Path=/\n..."
  }
}
```

Severity guide for this skill:
- critical — forged JWT accepted granting admin, auth bypass to admin, reset-flow
  account takeover of arbitrary users.
- high — cracked credentials, HMAC secret recovered, session fixation on a sensitive
  app, no session invalidation on logout + token theft vector present.
- medium — missing Secure/HttpOnly on session cookie, username enumeration with
  no lockout, CSRF on a state-changing endpoint, weak lockout.
- low — missing SameSite alone, verbose auth errors, long absolute timeout.
- info — concurrent sessions allowed (context-dependent), autocomplete on password.

Classification quick map: ATHN-02/CWE-521 weak creds · ATHN-03/CWE-307 lockout ·
ATHN-01/CWE-319 cleartext creds · reset flaws CWE-640 · JWT forgery CWE-347 ·
fixation WSTG-SESS-03/CWE-384 · cookie flags WSTG-SESS-02/CWE-614+CWE-1004 ·
lifecycle WSTG-SESS-06/07/CWE-613 · CSRF WSTG-SESS-05/CWE-352 ·
redirect_uri CWE-601.

Write the final narrative with the shared `finding-report` skill; record raw asset
coverage with the shared `coverage-assets` skill.
