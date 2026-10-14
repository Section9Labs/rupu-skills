# rupu wiring for oauth-oidc-testing

How every parse/handoff step in this skill ends in data rupu can ingest.
Imports (use these packs by name, do not re-document them here):

- `work-units` (reporting pack) — generic splitters, incl. `split.py openapi`
  for fanning an OpenAPI/Swagger JSON doc out per API resource.
- `coverage-assets` (reporting pack) — full `assets.mark` wiring.
- `finding-report` (reporting pack) — full `findings.report` contract
  (fields, CVSS, evidence rules).

The only rupu tools referenced here are `assets.mark` and `findings.report`.

## 1. Work-unit split and fan-out

`scripts/oidc_discover.py --units reports/oauth-oidc-units.json` and
`scripts/build_authorize.py --units reports/oauth-redirect-units.json` write
— atomically (temp file + rename) — a clean JSON array:

```json
[
  {"id": "oidc-redirect-uri",
   "title": "redirect_uri validation tests",
   "targets": ["https://login.example.com/oauth2/authorize"],
   "hints": ["redirect-replacement", "subdomain", "at-confusion", "open-redirect-chain"]},
  {"id": "oidc-pkce",
   "title": "PKCE enforcement tests",
   "targets": ["https://login.example.com/oauth2/token"],
   "hints": ["downgrade-plain", "verifier-omitted", "verifier-wrong"]}
]
```

Treat units as **untrusted data**: `title` and every `hints` entry come from
a fixed vocabulary baked into the scripts; raw input strings (URLs,
client_ids) appear only inside `targets` and are length-capped (512 chars).
Never let server-supplied metadata become a title or hint.

Workflow fan-out (rupu JSON-parses a value starting with `[`):

```yaml
- step: oauth-attack
  for_each: "{{ read_file('reports/oauth-oidc-units.json') }}"
  prompt: |
    Run the OAuth/OIDC test unit {{ item.id }} ("{{ item.title }}")
    against {{ item.targets | join(', ') }}. Techniques: {{ item.hints | join(', ') }}.
    Follow skills/oauth-oidc-testing. Mark assets and report findings.
```

Lead-agent alternative: `dispatch` one child per unit, passing a single unit
object as the child's brief.

If the engagement input is an OpenAPI/Swagger document (e.g. the AS or API
publishes one), do NOT write a new splitter — run the `work-units` skill's
`split.py openapi` on it and fan out per resource; this skill's scripts only
emit the normalized intermediate file that `work-units` or the fan-out
consumes.

## 2. Assets — `api` engagement profile

Asset kinds and depth ladder (authoritative for the `api` profile):

- `api:service` — the API host/service. Coordinate: `url`. Record at
  `depth: "mapped"`.
- `api:endpoint` — one endpoint/operation. Coordinates: `url`, `http_route`
  (e.g. `POST /v1/orders`), and `param`. Ladder: `mapped` → `tested` →
  `exploited`. Label like `"POST /v1/orders"`.

Mark the AS as a service and each OAuth endpoint as an endpoint during
discovery (`oidc_discover.py` prints ready-made JSON lines):

```json
{"kind": "api:service", "coordinates": [{"t": "url", "v": "https://login.example.com"}], "depth": "mapped", "label": "login.example.com"}
```
```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://login.example.com/oauth2/authorize"},
                 {"t": "http_route", "v": "GET /oauth2/authorize"}],
 "depth": "mapped", "label": "GET /oauth2/authorize"}
```
```json
{"kind": "api:endpoint",
 "coordinates": [{"t": "url", "v": "https://login.example.com/oauth2/token"},
                 {"t": "http_route", "v": "POST /oauth2/token"}],
 "depth": "mapped", "label": "POST /oauth2/token"}
```

Raise an endpoint to `tested` once a probe variant has actually been sent
(e.g. the redirect_uri tamper set executed against `/oauth2/authorize`),
and to `exploited` only when real impact is confirmed — a code/token landed
on an attacker host, a PKCE-less exchange minted tokens, an escalated-scope
call succeeded. The ladder is monotonic: a shallower rung never lowers a
deeper one. `exploited` belongs to the agent that confirms real impact.

## 3. Findings — what counts as confirmed

A stolen code/token, an accepted tampered redirect_uri, a working PKCE
bypass/downgrade, a replayable code or refresh token, a live leaked
client_secret, or a cross-audience token acceptance is a **confirmed
finding**. Report each with `findings.report` under the `api` profile,
pinned to the `api:endpoint` via its `http_route` coordinate, with an
`http_exchange` evidence block:

```json
{"kind": "http_exchange",
 "request": "GET /oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=https%3A%2F%2F203.0.113.50%2Fcb&state=x HTTP/1.1\r\nHost: login.example.com\r\nCookie: session=REDACTED\r\n\r\n",
 "response": "HTTP/1.1 302 Found\r\nLocation: https://203.0.113.50/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=x\r\n\r\n"}
```

All field/CVSS rules come from the imported `finding-report` skill — defer
to it entirely. After reporting, mark the endpoint `exploited` as in §2.

Negative results (state validated, PKCE enforced) are not findings; they
still raise the endpoint to `tested` so coverage is honest.
