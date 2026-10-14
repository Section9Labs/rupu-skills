# rupu wiring for access-control-testing

Every parse/handoff step in this skill ends in one of three rupu outputs:
a **work-units JSON array**, **`assets.mark`** calls, or a **`findings.report`**
call. This file pins the exact shapes.

## 1. Work units (fan-out of flagged matrix cells)

`scripts/authz_matrix.py --work-units wu.json` writes a clean JSON array whose
first character is `[` — rupu's `for_each:` JSON-parses it directly (via the
`read_file` tool), and a lead agent can `dispatch` one child per element. Hand
the array to the `work-units` skill for normalization/splitting before fan-out.

Element shape (one unit per flagged cell to confirm manually):

```json
[
  {
    "id": "authz-req12-userB",
    "title": "Confirm IDOR: userB got 200 on GET /api/users/1041 (owner: userA)",
    "targets": ["https://example.com/api/users/1041"],
    "hints": {
      "method": "GET",
      "owner_identity": "userA",
      "attacker_identity": "userB",
      "verdict": "CANDIDATE",
      "owner_status": "200",
      "attacker_status": "200",
      "owner_len": "2311",
      "attacker_len": "2298",
      "same_body": "false",
      "wstg": "WSTG-ATHZ-04",
      "cwe": "CWE-639",
      "next": "Diff bodies; if B's response contains A's data, report via finding-report skill"
    }
  }
]
```

All `hints` values are strings. `targets` carries the affected URL(s).

## 2. Assets (`assets.mark`, web profile — kinds are `web:`-prefixed)

Depth ladder: `mapped` -> `crawled` -> `tested` -> `exploited`. Mark the rung
actually reached. Record assets via the `coverage-assets` skill.

Site you captured traffic against (step 1):

```json
{"kind": "web:site", "label": "https://example.com",
 "coordinates": [{"t": "url", "v": "https://example.com"}],
 "depth": "mapped"}
```

Route captured by walking/crawling (step 1):

```json
{"kind": "web:route", "label": "GET /api/users/{id}",
 "coordinates": [{"t": "url", "v": "https://example.com"},
                  {"t": "http_route", "v": "/api/users/1041"},
                  {"t": "param", "v": "id"}],
 "depth": "crawled"}
```

Route run through the authz matrix (step 5) -> `"depth": "tested"`.
Route with confirmed cross-identity access or authz bypass (steps 2–4, 6)
-> `"depth": "exploited"`. The `param` coordinate is optional — include it when
the vulnerable reference is a named parameter.

`authz_matrix.py --assets assets.json` emits one such object per tested route
(`tested`, upgraded to `exploited` for CONFIRMED cells) for replay through
`assets.mark` / the `coverage-assets` skill.

## 3. Findings (`findings.report`)

The `web` profile completeness checks require all three of: finding pinned to a
route/url, an HTTP exchange in evidence, and an OWASP-or-CWE classification.
Use scope `endpoint` with `target_ref` = affected URL (scope `host` only for
host-wide issues, e.g. a trust-all `X-Forwarded-For` on every route). File each
via the `finding-report` skill.

```json
{
  "title": "IDOR: userB reads userA's profile at /api/users/1041",
  "scope": "endpoint",
  "target_ref": "https://example.com/api/users/1041",
  "severity": "high",
  "classification": "WSTG-ATHZ-04 / CWE-639 / OWASP A01:2021 (API1:2023 BOLA)",
  "evidence": {
    "rationale": "Object-level authorization is not enforced: a request for user object 1041 (owned by userA) returns the identical 200 body when replayed with userB's session token. Body sha256 matches the owner baseline, proving userB received userA's data.",
    "owner_exchange": "GET /api/users/1041 HTTP/1.1\nHost: example.com\nAuthorization: Bearer <userA>\n\nHTTP/1.1 200 OK\nContent-Length: 2311\n\n{\"id\":1041,\"email\":\"usera@example.com\",...}",
    "attacker_exchange": "GET /api/users/1041 HTTP/1.1\nHost: example.com\nAuthorization: Bearer <userB>\n\nHTTP/1.1 200 OK\nContent-Length: 2311\n\n{\"id\":1041,\"email\":\"usera@example.com\",...}"
  }
}
```

Severity guidance:
- cross-account **read** -> `high`
- cross-account **write/delete**, anon access to authenticated function, or
  user->admin escalation (incl. mass assignment to a role field) -> `critical`
- existence oracle / metadata-only leak -> `medium`

Classification picks: IDOR/BOLA = `WSTG-ATHZ-04 / CWE-639`; BFLA / forced
browse / header-path bypass = `WSTG-ATHZ-02 / CWE-285` (CWE-284 if anon);
vertical escalation / role tamper = `WSTG-ATHZ-03 / CWE-269`; mass assignment
= `WSTG-ATHZ-03 / CWE-915`.

`authz_matrix.py --findings findings.json` emits ready payloads in exactly this
shape for CONFIRMED cells — review each (confirm the body truly contains the
owner's data, not a shared static page) before filing.

## 4. Script input shapes (for completeness)

`requests.json` — the captured corpus (array):

```json
[
  {"id": "req12", "method": "GET", "url": "https://example.com/api/users/1041",
   "headers": {"Accept": "application/json"}, "body": null,
   "identity": "userA", "note": "own profile"}
]
```

`identities.json` — auth material + privilege rank (higher = more privileged;
include an empty-auth `anon` with `priv: 0`):

```json
{
  "anon":  {"priv": 0, "headers": {}},
  "userA": {"priv": 1, "headers": {"Authorization": "Bearer eyJ..A"}},
  "userB": {"priv": 1, "headers": {"Cookie": "session=abc..B"}, "cookies": {"extra": "1"}},
  "admin": {"priv": 2, "headers": {"Authorization": "Bearer eyJ..adm"}}
}
```

A mitmproxy addon that exports proxy capture into `requests.json`:

```python
# mitmdump -s export_requests.py -w capture.flows "~d example.com"
import json
from mitmproxy import http
OUT, seen = open("requests.json.lines", "a"), set()
def request(flow: http.HTTPFlow):
    key = (flow.request.method, flow.request.path.split("?")[0])
    if key in seen: return
    seen.add(key)
    OUT.write(json.dumps({
        "id": f"req{len(seen)}", "method": flow.request.method,
        "url": flow.request.url,
        "headers": dict(flow.request.headers),
        "body": flow.request.get_text() or None,
        "identity": "userA"}) + "\n")
    OUT.flush()
```

(then wrap the JSONL into a `[...]` array; the `work-units` skill's normalizer
or a one-liner handles that).
