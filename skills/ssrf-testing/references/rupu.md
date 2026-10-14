# rupu wiring — ssrf-testing

Every parse/handoff step in this skill ends in one of three rupu outputs:
a work-units JSON array, `assets.mark` calls, or a `findings.report` call.

## 1. Work units (fan-out over SSRF candidates)

`scripts/ssrf_probe.py work-units` (and `gen --work-units`) writes a clean JSON
array file whose **first character is `[`** so a rupu workflow `for_each:` can
JSON-parse it (read via the `read_file` tool), or a lead agent can read it and
`dispatch` one child per element. Normalize/split large arrays with the shared
`work-units` skill before fan-out.

Element shape:

```json
[
  {
    "id": "ssrf-example.com-fetch-url",
    "title": "SSRF candidate: url @ https://example.com/fetch",
    "targets": ["https://example.com/fetch?url=FUZZ"],
    "hints": {
      "param": "url",
      "method": "GET",
      "vuln_class": "ssrf",
      "cwe": "CWE-918",
      "wstg": "WSTG-INPV-19",
      "next_step": "run ssrf_probe.py gen with an interactsh callback, send probes, watch interactsh.jsonl"
    }
  }
]
```

## 2. Assets (coverage)

Record with the rupu `assets.mark` tool using the built-in `web` profile kinds
(profile-namespaced — prefix `web:`). Use the shared `coverage-assets` skill's
conventions. Depth ladder: `mapped` → `crawled` → `tested` → `exploited` — mark the
rung actually reached.

Site that was probed:

```json
{"kind": "web:site", "coordinates": [{"t":"url","v":"https://example.com"}],
 "label": "https://example.com", "depth": "mapped"}
```

Candidate route found by crawling:

```json
{"kind": "web:route",
 "coordinates": [{"t":"url","v":"https://example.com"},
                 {"t":"http_route","v":"/fetch"},
                 {"t":"param","v":"url"}],
 "label": "/fetch?url=", "depth": "crawled"}
```

After sending the SSRF probe set with no hit → re-mark the same route with
`"depth":"tested"`. After a confirmed OOB callback, metadata read, or gopher
interaction → `"depth":"exploited"`.

## 3. Findings

Confirmed SSRF → `findings.report` (compose the full writeup with the shared
`finding-report` skill). `scripts/ssrf_probe.py finding ... -o finding.json` emits
this exact payload. The `web` profile completeness checks require: finding pinned
to a route/url (`scope:endpoint` + `target_ref`), an HTTP exchange in evidence, and
an OWASP-or-CWE classification — satisfy all three.

```json
{
  "title": "SSRF in url parameter of /fetch (OOB-confirmed)",
  "scope": "endpoint",
  "target_ref": "https://example.com/fetch?url=",
  "severity": "high",
  "classification": {"cwe": "CWE-918", "wstg": "WSTG-INPV-19"},
  "evidence": {
    "rationale": "The url parameter is fetched server-side without validation. Injecting http://cbg3abc.oast.pro/p1-url produced DNS and HTTP interactions from the server's egress IP 192.0.2.55 (User-Agent curl/7.88.1), proving the server issues attacker-controlled requests (CWE-918).",
    "request": "GET /fetch?url=http%3A%2F%2Fcbg3abc.oast.pro%2Fp1-url HTTP/1.1\r\nHost: example.com\r\n...",
    "response": "HTTP/1.1 200 OK\r\n... (sink response)",
    "oob_interactions": [
      {"protocol":"dns","remote-address":"192.0.2.53","timestamp":"..."},
      {"protocol":"http","remote-address":"192.0.2.55","raw-request":"GET /p1-url HTTP/1.1\r\nHost: cbg3abc.oast.pro\r\nUser-Agent: curl/7.88.1\r\n","timestamp":"..."}
    ]
  }
}
```

Severity guidance:

| Result | Severity |
|---|---|
| OOB callback only (blind, external fetch proven) | high |
| Internal service reachable / response reflected | high |
| Cloud metadata credentials, k8s token, docker API, gopher-RCE | critical |
| DNS-only resolution, fetch demonstrably blocked | medium (document the differential) |

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| 1. Input discovery parse | work-units array (`ssrf-units.json`) → `work-units` skill; `assets.mark` web:route `mapped`/`crawled` |
| 2. OOB confirmation | hit → `findings.report` via `finding-report` skill + `assets.mark` `exploited`; no hit → `assets.mark` `tested` |
| 3. Internal/metadata targeting | each new result upgrades the finding (severity/evidence) via `findings.report`; internal hosts discovered become a new work-units array for fan-out |
| 4. Bypass attempts | success → finding evidence update; still blocked → `tested` + note in unit hints |
