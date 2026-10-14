# rupu wiring for the mitmproxy skill

Every parse/handoff step in this skill ends by producing one of three
rupu-ingestible outputs: a **work-units JSON array**, **`assets.mark`** calls, or a
**`findings.report`** call. This file gives the exact shapes.

## 1. Work units (fan-out over harvested endpoints)

`scripts/flows_to_targets.py --work-units wu.json` writes a clean JSON **array**
whose first character is `[` — rupu's `for_each:` JSON-parses such a file (read via
the `read_file` tool), and a lead agent can read the same file and `dispatch` one
child per element. Hand the array to the `work-units` skill for canonical
normalization/splitting before fan-out.

Element shape:

```json
[
  {
    "id": "post-api-example-com-api-v1-orders",
    "title": "POST https://api.example.com/api/v1/orders (params: coupon, qty)",
    "targets": ["https://api.example.com/api/v1/orders"],
    "hints": {
      "method": "POST",
      "host": "api.example.com",
      "path": "/api/v1/orders",
      "params": "coupon,qty",
      "content_type": "application/json",
      "status_seen": "200",
      "source": "mitmproxy-harvest"
    }
  }
]
```

All `hints` values are strings. One unit per deduplicated
method+host+path+param-set; children typically run sqlmap/dalfox/manual testing
against their unit's endpoint.

## 2. Assets (`assets.mark`)

Record what the capture proved exists, using the `web` profile kinds (prefix
`web:`). Follow the `coverage-assets` skill's conventions. The script's
`--assets assets.json` output is a JSON array of ready-to-send payloads:

```json
[
  {
    "kind": "web:site",
    "label": "https://api.example.com",
    "coordinates": [{"t": "url", "v": "https://api.example.com"}],
    "depth": "mapped"
  },
  {
    "kind": "web:route",
    "label": "POST /api/v1/orders (coupon)",
    "coordinates": [
      {"t": "url", "v": "https://api.example.com"},
      {"t": "http_route", "v": "/api/v1/orders"},
      {"t": "param", "v": "coupon"}
    ],
    "depth": "crawled"
  }
]
```

Depth ladder — mark the rung actually reached:

| depth | when (mitmproxy context) |
|---|---|
| `mapped` | host/route merely observed/probed (e.g. from a URL-list input) |
| `crawled` | route captured from real app usage through the proxy (the normal harvest case — use `--depth crawled`) |
| `tested` | you fuzzed it (e.g. `param_fuzz.py` replays) or handed it to a vuln tool that ran |
| `exploited` | issue confirmed on it (also file a finding) |

One `web:site` per scheme+host, one `web:route` per route; the script emits a
route element per parameter when parameters exist (param coordinate is optional
otherwise).

## 3. Findings (`findings.report`)

For issues confirmed through mitmproxy (tamper-and-replay auth bypass, parameter
reflection confirmed downstream, server honoring client-side-only controls),
write the finding via the `finding-report` skill. The `web` profile completeness
checks require all three of: finding pinned to a route/url, an HTTP exchange in
evidence, and an OWASP-or-CWE classification.

```json
{
  "title": "Broken access control: order history readable cross-tenant via replayed session",
  "scope": "endpoint",
  "target_ref": "https://api.example.com/api/v1/orders/1337",
  "severity": "high",
  "classification": "WSTG-ATHZ-02 / CWE-639",
  "evidence": {
    "rationale": "Replaying user A's captured GET /api/v1/orders/1337 with user B's session cookie (mitmdump -nC orders.mitm --modify-headers '/~q/Cookie/session=B-SESSION') returned user A's order with HTTP 200 instead of 403, proving object-level authorization is not enforced server-side.",
    "request": "GET /api/v1/orders/1337 HTTP/1.1\nHost: api.example.com\nCookie: session=B-SESSION\n\n",
    "response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"order_id\":1337,\"owner\":\"userA\",\"card_last4\":\"4242\"}"
  }
}
```

- Use scope `endpoint` with `target_ref` = affected URL; scope `host` only for
  host-wide issues (e.g. missing TLS everywhere).
- `severity`: info|low|medium|high|critical.
- Pull the exact request/response bytes from the flow file (`mitmdump -nr
  capture.mitm --set flow_detail=4 "~u /orders/1337"` or TUI `E` → raw) —
  flow files are the evidence source of truth.
- Classify by WSTG id (e.g. WSTG-ATHZ-02, WSTG-INPV-05, WSTG-SESS-09) and/or CWE.
- After reporting, re-mark the asset `exploited`.

## Step → output map

| Skill step | rupu output |
|---|---|
| §7 harvest normalize (`flows_to_targets.py`) | work-units array (`--work-units`) + `assets.mark` payloads (`--assets`) → `work-units` / `coverage-assets` skills |
| §6 fuzz addon hits (`param_fuzz.py` warns) | mark route `tested`; confirmed hits → `findings.report` via `finding-report` skill |
| §8 vuln-tool handoff results | downstream skill reports; mark routes `tested`/`exploited` |
| §4/§5 tamper-and-replay confirmations | `findings.report` (shape above) + asset depth `exploited` |
