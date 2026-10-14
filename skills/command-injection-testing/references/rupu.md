# rupu Wiring — command-injection-testing

Every parse/handoff step in this skill ends by producing one of three
rupu-ingestible outputs: a work-units JSON array, `assets.mark` calls, or
`findings.report` calls. `scripts/parse_cmdi.py` emits all three shapes.

## 1. Work units (fan-out)

A clean JSON ARRAY file whose first character is `[`. rupu's `for_each:`
JSON-parses it (read via the `read_file` tool); a lead agent reads the same
file and `dispatch`es one child per element. Hand the array to the
`work-units` skill for canonical splitting/normalizing before dispatch.

Element shape emitted by `parse_cmdi.py --work-units units.json`:

```json
[
  {
    "id": "cmdi-example.com-diag-addr",
    "title": "Exploit confirmed command injection: addr @ /diag",
    "targets": ["https://example.com/diag?addr=203.0.113.5"],
    "hints": {
      "param": "addr",
      "method": "GET",
      "separator": ";",
      "technique": "classic",
      "payload": ";echo UQQVZL$((61+40))$(echo UQQVZL)UQQVZL",
      "os": "unix",
      "next": "commix -u <url> -p addr --prefix=';' --batch --os-shell"
    }
  }
]
```

Un-confirmed-but-suspicious candidates (e.g. interactsh DNS hit without a
stable technique) also become work units, with `hints.status: "suspect"`.

## 2. Assets — `assets.mark`

Use the built-in `web` engagement profile kinds (profile-namespaced, prefix
`web:`). Depth ladder: `mapped` -> `crawled` -> `tested` -> `exploited`.
Record via the `coverage-assets` skill.

Site you probed:

```json
{
  "kind": "web:site",
  "label": "https://example.com",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "depth": "mapped"
}
```

Route + param you tested or exploited:

```json
{
  "kind": "web:route",
  "label": "GET /diag?addr — command injection (confirmed)",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/diag"},
    {"t": "param", "v": "addr"}
  ],
  "depth": "exploited"
}
```

Depth rules for this skill:
- candidate route identified from crawl/recon → `crawled`
- separators/blind/OOB probes sent, no confirmation → `tested`
- injection confirmed (output, scaling delay, or OOB callback) or shell
  obtained → `exploited`

## 3. Findings — `findings.report`

One finding per confirmed (url, param). Scope `endpoint`, `target_ref` = the
affected URL. Severity for confirmed OS command injection is `critical`
(remote command execution). Classification must carry OWASP and/or CWE —
this skill always sets both: `WSTG-INPV-12` and `CWE-78`.

The `web` profile completeness checks require all three of: finding pinned to
a route/url, an HTTP exchange in evidence, an OWASP-or-CWE classification.

```json
{
  "title": "OS command injection in 'addr' parameter of /diag",
  "scope": "endpoint",
  "target_ref": "https://example.com/diag?addr=203.0.113.5",
  "severity": "critical",
  "classification": {"owasp": "WSTG-INPV-12", "cwe": "CWE-78"},
  "evidence": {
    "rationale": "The 'addr' parameter is concatenated into a shell command. Injecting ';id' returned the output of id in the response body, proving arbitrary command execution as the web user (www-data). Technique: classic (results-based); separator ';'.",
    "request": "GET /diag?addr=203.0.113.5%3Bid HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n...PING 203.0.113.5...\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n...",
    "command_output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "payload": ";id",
    "oob": "dns interaction u1-addr.SESSION.oast.pro from 203.0.113.5 at 2025-06-01T12:00:00Z (only for OOB-confirmed cases)"
  }
}
```

Blind cases: `evidence.rationale` must state the proof mechanism (scaling
sleep deltas with the two measured timings, or the interactsh interaction
record with protocol/full-id/remote-address) and still include the triggering
HTTP request plus the (delayed/empty) response.

File each payload via the `finding-report` skill.

## 4. Where each methodology step lands

| Step | rupu output |
|---|---|
| 1. Candidate sinks listed | `assets.mark` web:route depth `mapped`/`crawled` |
| 2. Manual probes parsed | `parse_cmdi.py --manual` → work units + assets `tested`/`exploited` |
| 3. commix run parsed | `parse_cmdi.py --commix-dir` → work units + findings + assets `exploited` |
| 4. Shell / post-ex done | `findings.report` (via `finding-report` skill) with full exchange |
