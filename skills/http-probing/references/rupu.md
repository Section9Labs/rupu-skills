# rupu wiring for http-probing

Every parse/handoff step in this skill ends in exactly one of three
rupu-ingestible outputs: a **work-units JSON array**, **`assets.mark`** calls, or
a **`findings.report`** call. This file gives the exact shapes.

## 1. Work units (fan-out)

`scripts/parse_httpx.py --work-units units.json` writes a clean JSON **array**
file whose **first character is `[`**. rupu's workflow `for_each:` JSON-parses a
file value that begins with `[` (read via the `read_file` tool); a lead agent
reads the same file and `dispatch`es one child per element.

Element shape (one live site per unit):

```json
[
  {
    "id": "site-a1b2c3d4",
    "title": "Example Admin — https://app.example.com:8443",
    "targets": ["https://app.example.com:8443"],
    "hints": {
      "tech": ["Nginx:1.24.0", "React", "Express"],
      "status": 200,
      "server": "nginx/1.24.0",
      "ip": "203.0.113.7",
      "cdn": "cloudflare",
      "title": "Example Admin"
    }
  }
]
```

- `id` — stable (derived from the URL hash) so re-runs dedupe.
- `title` — page title if present, else the URL.
- `targets` — the probed URL(s); children run `web-crawling`,
  `content-discovery`, `nuclei`, `cms-testing`, `tls-testing` against it.
- `hints` — routing data; `hints.tech` is updated after the fingerprint merge.

Hand the array to the **`work-units`** skill (the canonical splitter/normalizer)
before dispatch — do not re-invent its normalization.

## 2. Assets — `assets.mark`

Record with the built-in `web` engagement profile kinds (profile-namespaced, so
prefix `web:`). Conventions per the **`coverage-assets`** skill.

Every live endpoint from the probe pass → one `web:site` at depth `mapped`:

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://app.example.com:8443"}],
  "depth": "mapped",
  "label": "https://app.example.com:8443 [200] Example Admin (nginx/1.24.0)"
}
```

`scripts/httpx_to_assets.py` prints these payloads one per line (or `--array`
for a single JSON array), ready to pass to the tool.

If the probe itself surfaced a notable route (e.g. a redirect landing on
`/login`, or `-mr` matched an admin path), mark it as a `web:route`:

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://app.example.com:8443"},
    {"t": "http_route", "v": "/login"}
  ],
  "depth": "mapped",
  "label": "/login (302 target)"
}
```

Depth ladder — mark the rung actually reached: `mapped` → `crawled` → `tested`
→ `exploited`. Probing and fingerprinting are **`mapped`**. Routes discovered by
the follow-on `web-crawling` skill are `crawled`; endpoints the follow-on skills
fuzz or vuln-test are `tested`; confirmed/exploited ones are `exploited`. This
skill only ever marks `mapped` — later skills promote the depth.

## 3. Findings — `findings.report`

Probing occasionally yields directly reportable issues (exposed management
console, version disclosure treated as a finding, debug endpoint on a high
port). File via the **`finding-report`** skill. Shape:

```json
{
  "title": "Exposed Grafana admin console on non-standard port",
  "scope": "endpoint",
  "target_ref": "https://app.example.com:3000/login",
  "severity": "medium",
  "classification": "CWE-200 / OWASP WSTG-CONF-05",
  "evidence": {
    "rationale": "Port-sweep probing found Grafana v9.1.0 (login page title and tech fingerprint) reachable without network restriction on tcp/3000; the version is disclosed in the page body and is below the current patched release.",
    "exchange": "GET /login HTTP/1.1\nHost: app.example.com:3000\n\nHTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n\n<title>Grafana</title>... \"version\":\"9.1.0\" ..."
  }
}
```

The `web` profile's completeness checks require all three of:
1. the finding **pinned to a route/url** — use scope `endpoint` with
   `target_ref` set to the affected URL (scope `host` only for host-wide
   issues);
2. an **HTTP exchange in evidence** — capture it with httpx `-irr` (full
   request/response in the JSON) or `-sr -srd responses/`, or re-fetch with
   curl and paste the exchange;
3. an **OWASP (WSTG id or Top-10) or CWE classification**.

`severity` ∈ info|low|medium|high|critical.

## Step → output map

| Skill step | rupu output |
|---|---|
| Step 1 probe parsed (Step 2) | work-units array (`units.json`) + `assets.mark` `web:site` @ `mapped` per endpoint |
| Step 3 fingerprint merge | updated `units.json` (via `work-units` skill) + re-`assets.mark` with tech labels; `findings.report` for anything directly reportable |
| Step 4 handoff | dispatch over `units.json` (`for_each:` / lead `dispatch`) |
