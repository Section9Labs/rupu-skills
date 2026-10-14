# rupu wiring — request-smuggling-testing

Every parse/handoff step in this skill ends in exactly one of: a **work-units JSON
array** (fan-out), **`assets.mark`** calls (coverage), or a **`findings.report`** call
(verified issue). This file gives the exact shapes.

## 1. Work units (fan-out over desync candidates)

`scripts/smuggle_probe.py --work-units candidates.json` writes a clean JSON array —
first character `[` — so a rupu workflow `for_each:` can JSON-parse it directly (via
`read_file`) and a lead agent can `dispatch` one child per element. Normalize or merge
arrays from multiple hosts with the shared **`work-units`** skill before fan-out.

Element shape:

```json
[
  {
    "id": "smuggle-clte-example.com-443",
    "title": "CL.TE desync candidate on https://example.com/",
    "targets": ["https://example.com/"],
    "hints": {
      "variant": "CL.TE",
      "mutation": "plain",
      "probe_b64": "UE9TVCAvIEhUVFAvMS4xDQpIb3N0Oi...",
      "evidence": "delay 10.02s vs baseline 0.31s",
      "next": "differential confirmation per references/desync.md"
    }
  },
  {
    "id": "hosthdr-xfh-example.com-reset",
    "title": "X-Forwarded-Host reflected in password-reset flow",
    "targets": ["https://example.com/forgot-password"],
    "hints": {"header": "X-Forwarded-Host", "attack": "password-reset-poisoning"}
  }
]
```

`hints` values are free-form but keep `variant`/`mutation` for desync units so the
child agent can rebuild the exact probe with
`smuggle_probe.py --probe <variant> --mutation <name>`.

## 2. Assets — `assets.mark` (web profile)

Mark the rung actually reached on the depth ladder
`mapped -> crawled -> tested -> exploited`.

```json
{"kind": "web:site",
 "coordinates": [{"t": "url", "v": "https://example.com"}],
 "label": "https://example.com",
 "depth": "mapped"}
```

After running smuggler.py / timing probes against a route:

```json
{"kind": "web:route",
 "coordinates": [{"t": "url", "v": "https://example.com"},
                 {"t": "http_route", "v": "/"}],
 "label": "POST / (desync probed: CL.TE, TE.CL, 13 TE.TE mutations)",
 "depth": "tested"}
```

A route with a confirmed/exploited desync, host-header bypass or cache poisoning gets
`"depth": "exploited"`. A route only discovered while mapping gets `"crawled"`.
Record assets through the shared **`coverage-assets`** skill.

## 3. Findings — `findings.report`

Write confirmed issues via the shared **`finding-report`** skill. The `web` profile
completeness checks require all three of: finding pinned to a route/url, an HTTP
exchange in evidence, and an OWASP-or-CWE classification. Template (also emitted by
`smuggle_probe.py --finding-template`):

```json
{
  "title": "HTTP request smuggling (CL.TE) via front-end/back-end desync",
  "scope": "endpoint",
  "target_ref": "https://example.com/",
  "severity": "high",
  "classification": {"cwe": "CWE-444", "owasp": "WSTG-INPV"},
  "evidence": {
    "rationale": "Front-end honors Content-Length while back-end honors Transfer-Encoding. Timing probe delayed 10.02s vs 0.31s baseline; differential confirmation: after smuggling a GET /404doesnotexist prefix, a fresh GET / returned 404 (baseline 200), proving the back-end socket was poisoned.",
    "http_exchange": "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 35\r\n\r\n0\r\n\r\nGET /404doesnotexist HTTP/1.1\r\nX-Ignore: X\n--- follow-up ---\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n=> HTTP/1.1 404 Not Found (baseline: 200 OK)",
    "artifacts": ["smuggler.log", "probe_timings.json"]
  }
}
```

Severity guidance:

- Timing + differential confirmed desync: **high**.
- Demonstrated response-queue poisoning, request capture, or cache poisoning hitting
  other users: **critical**.
- Host-header reflection with no demonstrated sink: **low/medium** (CWE-644); with
  reset poisoning or SSRF proven: **high** (CWE-640 / CWE-918).
- Web cache deception exposing authenticated content: **high** (CWE-525).

Use scope `endpoint` with `target_ref` = affected URL for all of these; use scope
`host` only when the desync is a property of the whole front-end (e.g. h2c upgrade
tunnelling that bypasses the edge for every route) — then still include one concrete
exchange in evidence.

## 4. Step-by-step wiring summary

| SKILL.md step | rupu output |
|---|---|
| §0 recon | `assets.mark` web:site depth `mapped` |
| §1 smuggler.py / h2csmuggler parse | work-units array (`--work-units`) -> `work-units` skill |
| §2 timing probes | `assets.mark` web:route depth `tested`; candidates -> work units |
| §3 differential confirmation | `findings.report` via `finding-report`; `assets.mark` depth `exploited` |
| §4 exploitation | upgrade existing finding severity; artifacts into evidence |
| §5 host header | diffs -> work units; confirmations -> `findings.report` |
| §6 cache poisoning/deception | Param Miner hits -> work units; confirmed -> `findings.report` + depth `exploited` |
