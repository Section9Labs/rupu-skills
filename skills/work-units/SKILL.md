---
name: work-units
description: Shared results-normalizer and work-unit splitter for the fleet. Converts heterogeneous recon/scan/analysis output (nmap XML, naabu/httpx JSONL, OpenAPI/Swagger specs, SARIF 2.1.0, Prowler OCSF, generic JSON/JSONL) into one clean JSON array of {id,title,targets,hints} work units that a rupu workflow for_each (via read_file) or a lead agent's dispatch can fan out over. Use at the end of every parse/handoff step in every pack so the next phase consumes stable units instead of raw scanner output.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# work-units — normalize tool output into fan-out-able work units

Every recon, scan, and analysis tool speaks a different format. rupu's `for_each:`
and a lead agent's `dispatch` both want one thing: **a clean JSON array of
independent items**. This skill is the single shared converter between those two
worlds. Every parse step in every other pack ends by running this splitter and
writing a work-unit array; every fan-out step starts by reading one.

## The work-unit contract

A work unit is a JSON object with exactly these four keys:

```json
{
  "id": "service-203-0-113-20-8443-tcp-9f2c41ab",
  "title": "203.0.113.20:8443/tcp https (nginx 1.18.0)",
  "targets": [
    { "type": "host", "value": "203.0.113.20" },
    { "type": "service", "value": "203.0.113.20:8443",
      "host": "203.0.113.20", "port": 8443, "protocol": "tcp" }
  ],
  "hints": {
    "service": "https", "product": "nginx", "version": "1.18.0",
    "source": "nmap"
  }
}
```

- **`id`** — stable, unique, slug-safe. Derived deterministically from the
  unit's *identity* (what it is, not which tool saw it):
  `slugify(identity)[:48] + "-" + sha1(identity)[:8]`. The identity string is
  built from the unit kind plus its natural key — `service|<host>|<port>|<proto>`,
  `url|<url>`, `route|<METHOD>|<path>|<base>`, `code|<rule>|<file>|<line>|<col>`,
  `finding|<finding uid>`. Because the identity is *tool-agnostic*, re-running
  the splitter over the same input yields the same ids (so `for_each` resume
  stays stable), and the same service seen by naabu and nmap gets the **same
  id**, which is what lets `merge.py` collapse them into one unit.
- **`title`** — short human label: `"203.0.113.20:8443/tcp https (nginx 1.18.0)"`,
  `"POST /api/v2/orders — example.com"`, `"js/sql-injection — src/db.js:42"`.
  This is what shows up in dispatch prompts and progress logs.
- **`targets`** — list of the concrete things the unit acts on. Each target is a
  small structured object `{"type": ..., "value": ..., ...}` — types in use:
  `host`, `service`, `url`, `http_route`, `file`, `cloud_resource`. Structured
  targets mean downstream agents never re-parse `"host:port"` strings.
- **`hints`** — only what the source actually provides, keyed plainly:
  service/product/version, scheme, status, title, tech, operation_id, security,
  rule_id, level, cwe, tags, check_id, severity, compliance, region, account,
  plus `source` (the tool) and a raw reference where useful. Empty values are
  dropped.

## THE one output rule

> **The output file MUST be a clean top-level JSON array and nothing else.**
> No log lines, no banner, no trailing prose, no JSONL. rupu's `for_each:`
> JSON-parses any rendered value that starts with `[` — so
> `for_each: "{{ read_file('reports/units.json') }}"` works if and only if the
> file is exactly one JSON array. The splitter guarantees this: all
> diagnostics go to stderr, only the array goes to stdout/`-o`.

Reading is forgiving (malformed JSONL lines are skipped with a note on stderr,
never aborting the run); writing is strict.

## The splitter: `scripts/split.py`

```
python3 scripts/split.py <kind> [INPUT] [-o OUT] [kind options]
```

INPUT defaults to stdin, OUT defaults to stdout. One dependency-free file, one
function per kind. Kinds and the command that produces their input:

| kind      | input format                         | produced by                              | one unit per |
|-----------|--------------------------------------|------------------------------------------|--------------|
| `nmap`    | nmap XML                             | `nmap -sV -oX scan.xml ...`              | open service (or host with `--group-by-host`) |
| `naabu`   | JSONL                                | `naabu -json -o ports.jsonl ...`         | host:port |
| `httpx`   | JSONL                                | `httpx -json -o web.jsonl ...`           | live URL |
| `openapi` | OpenAPI 3 / Swagger 2 **JSON**       | API spec download / `swagger.json`       | (path, method) operation |
| `sarif`   | SARIF 2.1.0 JSON                     | semgrep/CodeQL/`trivy -f sarif`/etc.     | `runs[].results[]` entry |
| `prowler` | OCSF JSON array or JSONL             | `prowler aws -M json-ocsf ...`           | cloud finding |
| `json`    | generic JSON array or JSONL          | anything already structured              | record |

Examples:

```sh
# nmap service scan -> one unit per open service
nmap -sV -sC -p- -oX reports/scan.xml 203.0.113.0/24
python3 scripts/split.py nmap reports/scan.xml -o reports/units.json

# naabu piped straight through
naabu -host example.com -top-ports 1000 -json -silent \
  | python3 scripts/split.py naabu -o reports/ports-units.json

# httpx probe of discovered services
httpx -l hosts.txt -json -title -tech-detect -o reports/web.jsonl
python3 scripts/split.py httpx reports/web.jsonl -o reports/web-units.json

# OpenAPI spec -> one unit per operation (YAML specs: convert to JSON first —
# the stdlib has no YAML parser; use the API's /openapi.json, or any converter)
python3 scripts/split.py openapi api/openapi.json \
  --base-url https://example.com/api -o reports/api-units.json

# SARIF from a code scanner
python3 scripts/split.py sarif reports/semgrep.sarif -o reports/code-units.json

# Prowler cloud findings, failures only
python3 scripts/split.py prowler reports/prowler-ocsf.json --fail-only \
  -o reports/cloud-units.json

# A tool the fleet hasn't special-cased
python3 scripts/split.py json custom.jsonl \
  --id-field vuln_id --title-field name --target-field endpoint \
  -o reports/custom-units.json
```

Per-kind options:

- `nmap --group-by-host` — one unit per host with all of its open services in
  `targets` (use when the downstream worker wants whole hosts, e.g. per-host
  exploitation agents). Default is one unit per open service.
- `openapi --base-url URL` — override/supply the server base (otherwise taken
  from `servers[0].url` or Swagger 2 `schemes`/`host`/`basePath`).
- `prowler --fail-only` — keep only `status_code: FAIL` findings.
- `json --id-field F --title-field F --target-field F` — override which record
  fields become id/title/targets; everything else lands in `hints`.

Field-by-field mapping for every kind is in [references/formats.md](references/formats.md).

## Merging phases: `scripts/merge.py`

A pipeline that ran naabu, then httpx, then nmap has three unit arrays
describing overlapping assets. Merge them into ONE list for handoff:

```sh
python3 scripts/merge.py reports/ports-units.json reports/web-units.json \
  reports/scan-units.json -o reports/units.json
```

De-duplicates by `id` (deterministic ids make cross-tool dedup work): the first
occurrence wins its position and scalar hints; later units contribute any
targets and hint keys the earlier one lacked, lists are unioned, nothing is
duplicated. Output: one clean JSON array.

## Handing off: rupu `for_each` and lead-agent `dispatch`

Full wiring with complete workflow YAML is in [references/rupu.md](references/rupu.md).
The short form:

```yaml
# upstream step (bash or agent) wrote reports/units.json as a clean JSON array
- id: attack
  agent: service-attacker
  for_each: "{{ read_file('reports/units.json') }}"
  max_parallel: 4
  prompt: |
    Work unit {{ item.id }} ({{ loop.index }}/{{ loop.length }}): {{ item.title }}
    Targets: {{ item.targets | tojson }}
    Hints:   {{ item.hints | tojson }}
```

A fleet lead does the same by reading the array and calling
`dispatch { kind: "agent", name, prompt }` once per unit, embedding
`targets`/`hints` into each child's prompt.

**The handoff rule every pack follows:** each parse step ends by producing a
work-unit array with this splitter. The next phase — enumeration, exploitation,
reporting — consumes `{id,title,targets,hints}`, never raw scanner output.
Downstream consumers imported by name: `coverage-assets` (feeds the same
units/inventory to `assets.mark`) and `finding-report` (records verified issues
with `findings.report`).

## Checklist for a parse step

1. Run the tool in its machine format (`-oX`, `-json`, `-M json-ocsf`, SARIF).
2. `python3 scripts/split.py <kind> <input> -o reports/<phase>-units.json`.
3. If multiple tools ran, `python3 scripts/merge.py ... -o reports/units.json`.
4. Confirm the file starts with `[` and parses: `python3 -c "import json;print(len(json.load(open('reports/units.json'))))"`.
5. Hand off: `for_each: "{{ read_file('reports/units.json') }}"` or per-unit `dispatch`.
