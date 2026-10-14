# rupu wiring for the burp-suite skill

Every parse/handoff step in this skill ends by producing one of three
rupu-ingestible outputs: a **work-units JSON array**, **`assets.mark`** calls,
or a **`findings.report`** call. This file pins the exact shapes.

Shared skills to import by name (same rupu-skills library — do not reinvent):
- **`work-units`** — canonical splitter/normalizer; hand it every work-units
  array this skill emits.
- **`coverage-assets`** — recording assets consistently; use its conventions
  when calling `assets.mark`.
- **`finding-report`** — writing a complete finding; use it to file every
  payload from `--findings` output after confirmation.

## 1. Work units (fan-out)

Written as a clean JSON **array** file whose first character is `[` so a rupu
workflow `for_each:` can JSON-parse it (via `read_file`) and a lead agent can
`dispatch` one child per element.

Element shape (what `scripts/burp_scan.py --work-units` and
`scripts/parse_burp_xml.py --work-units` emit — one unit per issue needing
confirmation):

```json
[
  {
    "id": "burp-issue-003",
    "title": "Confirm: SQL injection at https://example.com/product?id=1",
    "targets": ["https://example.com/product?id=1"],
    "hints": {
      "tool": "burp",
      "issue_name": "SQL injection",
      "issue_type": "1049088",
      "severity": "high",
      "confidence": "firm",
      "cwe": "CWE-89",
      "wstg": "WSTG-INPV-05",
      "next": "replay in Repeater; escalate with sqlmap -r req.txt --batch --technique=BEUSTQ"
    }
  }
]
```

Mapping-phase fan-out (SKILL.md §2) uses the same shape, one unit per
interesting route, `hints.next` describing the test class to run.

## 2. Assets — `assets.mark`

Use the `web` engagement profile kinds (profile-namespaced → prefix `web:`).
Depth ladder: `mapped` → `crawled` → `tested` → `exploited`; mark the rung
actually reached.

Site (probed/mapped target):

```json
{
  "kind": "web:site",
  "label": "https://example.com",
  "coordinates": [{"t": "url", "v": "https://example.com"}],
  "depth": "mapped"
}
```

Route found by crawling / site-map walking:

```json
{
  "kind": "web:route",
  "label": "GET /product?id",
  "coordinates": [
    {"t": "url", "v": "https://example.com"},
    {"t": "http_route", "v": "/product"},
    {"t": "param", "v": "id"}
  ],
  "depth": "crawled"
}
```

(`param` coordinate optional — include it when a specific parameter was the
subject.)

Depth per Burp activity:
| Activity | depth |
|---|---|
| Target added, proxy configured, first probe | `mapped` on `web:site` |
| Route appears in site map / crawl output | `crawled` on `web:route` |
| Repeater probing, Intruder fuzzing, Scanner audit of the route | `tested` |
| Confirmed exploitation (data retrieved, Collaborator exfil, shell) | `exploited` |

## 3. Findings — `findings.report`

Web issues use scope `endpoint` with `target_ref` = the affected URL (scope
`host` only for host-wide issues such as TLS misconfig). The `web` profile's
completeness checks require all three of: finding pinned to a route/url, an
HTTP exchange in evidence, and an OWASP-or-CWE classification.

Shape (what the scripts emit per issue in `--findings` output):

```json
{
  "title": "SQL injection in id parameter of /product",
  "scope": "endpoint",
  "target_ref": "https://example.com/product?id=1",
  "severity": "high",
  "classification": {"cwe": "CWE-89", "owasp": "WSTG-INPV-05"},
  "evidence": {
    "rationale": "Burp Scanner (confidence: firm) flagged SQL injection; replaying the attached request with payload '' produced a database error / differential response, establishing injectable SQL context in the id parameter.",
    "http_exchange": {
      "request": "GET /product?id=1'' HTTP/1.1\r\nHost: example.com\r\n...",
      "response": "HTTP/1.1 500 Internal Server Error\r\n...You have an error in your SQL syntax..."
    }
  }
}
```

Severity mapping from Burp: `high→high`, `medium→medium`, `low→low`,
`info/information→info`, `false_positive→info` (and drop after triage).
Escalate to `critical` manually when exploitation proves full compromise
(RCE, auth bypass to admin, mass data access) — Burp has no critical tier.

Confidence handling: `certain` findings may be filed directly; `firm` and
`tentative` MUST be replayed/confirmed (Repeater, sqlmap, Collaborator) before
`findings.report` — until then they live only as work units.

Collaborator-confirmed blind findings: include BOTH the injected request and
the interaction record (type, timestamp, source IP, inbound HTTP request if
any) in `evidence`; rationale states the causal link ("payload subdomain
x7k2…oastify.com injected only into the `url` parameter; DNS+HTTP interaction
received 3s after send → server-side fetch, CWE-918 / WSTG-INPV-19").

## 4. Classification cheat table (scripts implement this by issue-name keyword)

| Burp issue name contains | CWE | OWASP/WSTG |
|---|---|---|
| SQL injection | CWE-89 | WSTG-INPV-05 |
| Cross-site scripting (reflected) | CWE-79 | WSTG-INPV-01 |
| Cross-site scripting (stored) | CWE-79 | WSTG-INPV-02 |
| Cross-site scripting (DOM) | CWE-79 | WSTG-CLNT-01 |
| OS command injection | CWE-78 | WSTG-INPV-12 |
| XML external entity | CWE-611 | WSTG-INPV-07 |
| Server-side template injection | CWE-1336 | WSTG-INPV-18 |
| Server-side request forgery | CWE-918 | WSTG-INPV-19 |
| File path traversal / manipulation | CWE-22 | WSTG-ATHZ-01 |
| Open redirection | CWE-601 | WSTG-CLNT-04 |
| Cross-site request forgery | CWE-352 | WSTG-SESS-05 |
| HTTP request smuggling | CWE-444 | WSTG-INPV-15 |
| Deserialization | CWE-502 | OWASP-Top10:A08:2021 |
| CORS misconfiguration | CWE-942 | WSTG-CONF-11 |
| Session token / weak randomness | CWE-330 | WSTG-SESS-01 |
| Cleartext / TLS / certificate | CWE-319 | WSTG-CRYP-03 |
| Information disclosure / error message | CWE-209 | WSTG-ERRH-01 |
| (fallback) | CWE-693 | OWASP-Top10:A05:2021 |

## 5. Step-by-step wiring summary

| SKILL.md step | rupu output |
|---|---|
| §1 Setup | `assets.mark` `web:site` depth `mapped` |
| §2 Mapping | `assets.mark` `web:route` depth `crawled` + work-units array → `work-units` skill |
| §3 Repeater | `assets.mark` depth `tested`; confirmed → `finding-report` skill |
| §4 Intruder | `assets.mark` depth `tested`; anomalies → work units; confirmed → findings |
| §5 Scanner | `burp_scan.py`/`parse_burp_xml.py` → merged JSON + `--work-units` + `--findings` |
| §6 Collaborator | confirmed OOB → `findings.report` (depth `exploited` on the route) |
| §8 Headless/REST | same as §5, pipeline-driven |
| §9 Chaining out | downstream tool results re-enter via their own skills; routes handed off stay marked `tested` |
