---
name: nuclei
description: Template-driven vulnerability and misconfiguration scanning with ProjectDiscovery nuclei — sweep a live-endpoint inventory for known CVEs, exposures, default creds, and misconfigurations, fingerprint technologies to route follow-on testing, and author custom YAML templates for app-specific bugs. Use after http-probing has produced a live target list.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# nuclei — template-driven vulnerability scanning

nuclei matches thousands of community-maintained YAML templates (CVEs, exposures,
misconfigurations, default logins, takeovers, tech fingerprints) against HTTP(S)
targets at high speed. It is the first sweep you run once `http-probing` has given
you a list of live URLs, and the engine you use to codify any app-specific bug as
a reusable template.

Full flag reference and JSONL field dictionary: `references/running-and-tuning.md`.
Template authoring (matchers, extractors, payloads, interactsh, DAST/fuzzing):
`references/templates.md`. rupu wiring (work units, assets, findings):
`references/rupu.md`.

## 0. Setup

```sh
nuclei -version
nuclei -ut            # -update-templates: pull latest nuclei-templates
nuclei -update        # update the engine binary itself
nuclei -tl | wc -l    # list available templates (sanity check the install)
```

Templates land in `~/nuclei-templates/`. Re-run `-ut` at the start of every
engagement — new CVE templates land daily.

## 1. Running scans

Single target vs list input (feed the httpx/http-probing output directly —
nuclei accepts full URLs with scheme and port):

```sh
nuclei -u https://192.0.2.10:8443
nuclei -l live-urls.txt -o nuclei-raw.txt -jsonl -je nuclei.jsonl
```

### Template selection

Pick templates by path, tags, severity, author, or arbitrary condition. Combine
filters; they intersect.

```sh
# Everything (default: all templates minus code/headless/fuzz unless enabled)
nuclei -l live-urls.txt -je full.jsonl

# By directory / file
nuclei -l live-urls.txt -t http/cves/ -t http/exposures/ -je cves.jsonl
nuclei -t ./mytemplate.yaml -u https://example.com -debug

# By tags / severity / author
nuclei -l live-urls.txt -tags cve,rce,lfi,sqli -je tagged.jsonl
nuclei -l live-urls.txt -s critical,high -je crit-high.jsonl        # -severity
nuclei -l live-urls.txt -a geeknik -je by-author.jsonl              # -author

# Template-condition DSL (arbitrary metadata expressions)
nuclei -l live-urls.txt -tc "contains(tags,'cve') && contains(tags,'2024')"

# Exclusions
nuclei -l live-urls.txt -et http/fuzzing/ -etags dos,intrusive
```

### Automatic / tech-driven scan

`-as` / `-automatic-scan` runs wappalyzer-based tech detection first, then
executes only templates whose tags match the detected stack:

```sh
nuclei -l live-urls.txt -as -je autoscan.jsonl
```

### Technology fingerprinting pass

Run the tech templates on their own early — their output routes targets to the
right follow-on skill (`cms-testing` for WordPress/Joomla/Drupal hits,
`tls-testing` for TLS-terminating services, manual skills for frameworks):

```sh
nuclei -l live-urls.txt -t http/technologies/ -tags tech -je tech.jsonl
```

## 2. Tuning, auth, OOB, and output

```sh
nuclei -l live-urls.txt \
  -rl 150 -c 25 -bs 25 -timeout 10 -retries 1 \
  -H "Cookie: session=abc123" -H "Authorization: Bearer eyJ..." \
  -V domain=example.com -V apikey=XYZ \
  -silent -stats \
  -je nuclei.jsonl -o nuclei.txt -markdown-export ./md-report -sarif-export nuclei.sarif
```

- `-rl` requests/second (default 150), `-c` concurrent templates (default 25),
  `-bs` bulk size = parallel hosts per template (default 25), `-timeout`,
  `-retries`.
- `-H`/`-header` for cookies/auth headers; `-V`/`-var` sets `{{variables}}` used
  inside templates.
- `-headless` enables headless/DOM templates (needs Chrome); pair with
  `-tags headless` or let full runs include them.
- Out-of-band (blind) detection uses interactsh by default. Self-host with
  `-iserver https://interact.example.net` (+ `-itoken`); disable with
  `-no-interactsh` (blind SSRF/RCE/OOB templates then can't confirm).
- Machine-readable output is `-jsonl` (stdout) and `-je file.jsonl`
  (file export). There is **no `-json` flag**. Note: `-td` on nuclei means
  *template display*, not tech-detect.

Full tuning table in `references/running-and-tuning.md`.

## 3. Reading results and parsing (rupu handoff)

Each JSONL line is one match. Key fields:

- `template-id` — e.g. `CVE-2021-44228`
- `info.name`, `info.severity`, `info.tags`
- `info.classification.cve-id`, `info.classification.cwe-id`, `cvss-score`
- `matched-at` — the exact vulnerable URL (pin findings here)
- `extracted-results` — versions, tokens, paths pulled by extractors
- `request` / `response` — the raw HTTP exchange (evidence)
- `matcher-name`, `curl-command`, `host`, `timestamp`

Parse with the bundled script — this is the **required** rupu-ingest step:

```sh
python3 scripts/parse_nuclei.py nuclei.jsonl tech.jsonl \
  --merged merged.json \
  --work-units units.json \
  --findings findings.json \
  --assets assets.json
```

- `merged.json` — deduped normalized matches.
- `units.json` — a JSON array of work units (one per non-info match needing
  manual confirmation). Hand it to the `work-units` skill / a rupu `for_each:`
  so each candidate gets a dedicated confirmation pass.
- `assets.json` — `assets.mark` payloads (`web:site` / `web:route`, depth
  `tested`; bump a route to `exploited` once a match is confirmed). Record them
  via the `coverage-assets` skill.
- `findings.json` — pre-built `findings.report` payloads (scope `endpoint`,
  `target_ref` = matched-at, severity mapped, HTTP exchange + CVE/CWE in
  evidence). After manual confirmation of each work unit, file the issue via
  the `finding-report` skill using these payloads as the base. Info-severity
  tech-detect lines are not findings — they are routing data.

Exact JSON shapes: `references/rupu.md`.

Triage order: `critical`/`high` with a CVE id first (usually directly
exploitable — confirm with the `curl-command` or by re-running the single
template with `-debug`), then `medium` exposures (panels, debug endpoints,
backup files — chase each for creds/data), then `low`/`info` for attack-surface
context and tech routing.

## 4. Workflows

Workflows chain templates conditionally: run detection first, and only run the
matching exploit/enum templates on hosts where it hit. Run shipped workflows
with `-w`:

```sh
nuclei -l live-urls.txt -w workflows/wordpress-workflow.yaml -je wp.jsonl
```

Workflow YAML (`subtemplates` only execute when the parent matched; `matcher-name`
gates on a specific matcher):

```yaml
id: jira-workflow
info:
  name: Jira detect-then-exploit
workflows:
  - template: http/technologies/jira-detect.yaml
    subtemplates:
      - tags: jira,cve
```

Prefer `-as` for broad tech-conditional scanning; write a workflow when you need
an explicit, repeatable chain for one product.

## 5. Custom templates

Codify any app-specific bug you find manually. Minimal shape:

```yaml
id: example-debug-exposure
info:
  name: Example App Debug Endpoint Exposure
  author: operator
  severity: high
  tags: exposure,debug
  classification:
    cwe-id: CWE-489
http:
  - method: GET
    path:
      - "{{BaseURL}}/debug/vars"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "cmdline"
          - "memstats"
        condition: and
    extractors:
      - type: regex
        regex:
          - '"GOMAXPROCS":\s*\d+'
```

Core model (worked examples and the full matcher/extractor/payload reference in
`references/templates.md`):

- `http` requests: `method`+`path` lists, `headers`, `body`, or `raw:` full
  requests (multi-step with `cookie-reuse: true` for login-then-exploit).
- Matchers: `status`, `word`, `regex`, `binary`, `size`, `dsl`
  (e.g. `dsl: ["status_code==200 && contains(body,'root:')"]`), `part:`
  header/body/all, `negative: true`, `matchers-condition: and|or`.
- Extractors: `regex`, `kval` (headers/cookies), `json` (jq-style), `xpath`,
  `dsl`; `internal: true` to feed later requests as `{{name}}`.
- `payloads:` + `attack: batteringram|clusterbomb|pitchfork` turn a template
  into a fuzzer (wordlists inline or by file path).
- `{{interactsh-url}}` anywhere in a request gives blind/OOB detection; match
  with `part: interactsh_protocol` words `dns`/`http`.

Validate and debug:

```sh
nuclei -t ./mytemplate.yaml -validate                      # lint syntax
nuclei -t ./mytemplate.yaml -u https://192.0.2.10 -debug   # full req/resp
nuclei -t ./mytemplate.yaml -u https://192.0.2.10 -debug-req   # requests only
```

### DAST / fuzzing templates

Fuzzing templates mutate parameters of URLs you feed in (so feed URLs **with**
query strings — katana/gau output):

```sh
nuclei -l urls-with-params.txt -dast -je dast.jsonl        # (-fuzz is deprecated)
```

Fuzz-template syntax (`fuzzing:` sections, `part: query|path|header|cookie|body`,
`type: replace|postfix|prefix|infix`) is covered in `references/templates.md`.

## 6. Chaining

- **In**: live URL inventory from `http-probing` (httpx `-json` output → URL
  list); parameterized URLs from crawling skills for `-dast`.
- **Out**:
  - Non-info matches → work-units array → manual confirmation → verified issues
    filed via the `finding-report` skill (`findings.report`, scope `endpoint`).
  - Tech-detect matches → route targets: WordPress/Joomla/Drupal →
    `cms-testing`; TLS endpoints → `tls-testing`; frameworks/panels → the
    relevant manual vuln skills.
  - Every scanned site/route → `assets.mark` via the `coverage-assets` skill.
