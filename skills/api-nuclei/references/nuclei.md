# nuclei v3 reference for API scanning

Verified against public ProjectDiscovery nuclei v3 documentation. Flags shift
between minor releases — `nuclei -h` (and `nuclei -h` with `-hc` for config
help) on your build is authoritative, especially for DAST flags.

## Targeting

| Flag | Meaning |
|---|---|
| `-u`, `-target` | target URL/host; repeatable (`-u a -u b`) |
| `-l`, `-list` | file with one target per line (URLs with paths are honored) |
| `-im`, `-input-mode` | input file format: `list` (default), `openapi`, `swagger`, `postman`, `burp`, `jsonl`, `yaml` |
| `-H`, `-header` | custom header/cookie, repeatable: `-H "Authorization: Bearer eyJ..."` `-H "X-API-Key: k"` |
| `-V`, `-var` | template variable `key=value` |
| `-resume` | resume from a resume file |
| `-sa`, `-scan-all-ips` | scan all IPs behind a DNS record |

`-im openapi -l spec.json` parses the spec into concrete requests (paths,
methods, parameters, bodies) — the right way to feed nuclei an API. Same for
`-im burp -l export.xml` (Burp XML history) and `-im postman -l coll.json`.

## Template selection

| Flag | Meaning |
|---|---|
| `-t`, `-templates` | template file/dir/URL; repeatable: `-t http/exposures/apis/ -t http/cves/2024/` |
| `-id`, `-template-id` | run by template ID: `-id exposed-swagger-ui,springboot-actuator` |
| `-tags` | run templates carrying any of these tags |
| `-etags`, `-exclude-tags` | exclude by tag (e.g. `-etags dos,fuzz`) |
| `-exclude-id`, `-eid` | exclude by template ID |
| `-severity`, `-s` | filter: `critical,high,medium,low,info,unknown` |
| `-es`, `-exclude-severity` | inverse of `-severity` |
| `-a`, `-author` | filter by template author |
| `-tc`, `-template-condition` | expression-based selection, e.g. `-tc "contains(tags,'api') && severity=='high'"` |
| `-nt`, `-new-templates` | only templates added in the latest release |
| `-as`, `-automatic-scan` | wappalyzer tech detection → automatic tag mapping |
| `-ut`, `-update-templates` | update the template repo |
| `-tl` | list all available templates |
| `-validate` | syntax-check templates and exit |
| `-code` | enable `code:` protocol templates (local command execution templates — needs signed templates) |

### API-relevant template geography (in `~/nuclei-templates`)

- `http/exposures/apis/` — swagger/openapi UI+JSON, GraphQL (introspection,
  GraphiQL, playground, voyager), Spring Boot actuator endpoints, WADL, WSDL,
  Drupal/WordPress REST, api-console artifacts.
- `http/exposures/configs/`, `http/exposures/files/` — `.env`, config dumps,
  backup files, `.git` exposure.
- `http/exposures/tokens/` — leaked API keys, JWTs, cloud credentials
  (per-provider token regex templates).
- `http/misconfiguration/` — CORS (`cors-misconfig`), debug modes, directory
  listing, default installs, unauth admin panels, proxy misconfigs,
  springboot subdir, prometheus/metrics exposure.
- `http/cves/<year>/` — CVE checks; combine `-tags cve` with a tech tag.
- `http/technologies/` (`-tags tech`) — fingerprinting (feeds CVE pass).
- `http/default-logins/` — default credentials (gateways, dashboards).
- `http/takeovers/` — dangling CNAME/service takeover.
- `dast/` — fuzzing templates (SQLi, XSS, SSTI, LFI/traversal, SSRF, CMDi,
  redirect, header injection); selected only in `-dast` mode or via
  `-tags dast,fuzz`.

Useful tag sets for APIs:
`exposure,misconfig,api,swagger,graphql,jwt,token,config,cve,tech,default-login,takeover`.

## DAST / fuzzing mode (v3)

`-dast` restricts the run to fuzzing templates and enables param fuzzing on
parsed input requests. Older `-fuzz` / `-fuzzing-templates` flags are
deprecated and folded into `-dast` + the `dast/` templates. Confirm exact
names with `nuclei -h`.

| Flag | Meaning |
|---|---|
| `-dast` | run only DAST/fuzzing templates |
| `-ft`, `-fuzzing-type` | override payload placement: `replace`, `prefix`, `postfix`, `infix` |
| `-fm`, `-fuzzing-mode` | override mode: `multiple` (all params at once) or `single` (one at a time) |
| `-fa`, `-fuzz-aggression` | payload volume: `low` (default), `medium`, `high` |
| `-fuzz-param-frequency` | skip a parameter after N non-matching fuzz attempts (default 10) |
| `-cs`, `-crawl-scope` | in-scope URL regex for the fuzz space |
| `-cos`, `-crawl-out-scope` | out-of-scope URL regex |
| `-dtl`, `-dast-template-list`* | list DAST templates (*check `-h`) |

Fuzzing works on *parsed parameters*: query strings, body fields (form/JSON/
XML/multipart), headers, cookies, path segments — which is why the input must
carry real requests (`-im openapi|burp|postman`, or URLs that include query
params). A bare path list gives DAST almost nothing to fuzz.

### `fuzzing:` template structure (high level)

```yaml
id: example-sqli-error
info:
  name: Error-based SQLi (fuzz)
  severity: high
  tags: dast,fuzz,sqli
http:
  - pre-condition:            # optional gate on the incoming request
      - type: dsl
        dsl: ["method == 'GET'"]
    payloads:
      inj: ["'", "\"", "';--"]
    fuzzing:
      - part: query           # query|path|header|cookie|body|request
        type: postfix         # replace|prefix|postfix|infix
        mode: multiple        # multiple|single
        fuzz: ["{{inj}}"]
    stop-at-first-match: true
    matchers:
      - type: word
        part: body
        words: ["SQL syntax", "ORA-01756", "SQLSTATE["]
```

`part` picks what to fuzz, `type` how the payload is placed relative to the
original value, `mode` whether params are fuzzed together or individually.
`keys:`/`keys-regex:`/`values:` filters (under the fuzzing rule) restrict
which parameter names/values get fuzzed. Blind templates match on interactsh
interactions instead of response content.

## OOB / interactsh

| Flag | Meaning |
|---|---|
| `-iserver`, `-interactsh-server` | self-hosted interactsh URL, e.g. `https://oast.example.net` |
| `-itoken`, `-interactsh-token` | auth token for that server |
| `-interactions-cache-size` / `-eviction` / `-cooldown-period` / `-poll-duration` | polling tuning |
| `-ni`, `-no-interactsh` | disable OOB (kills blind SSRF/SQLi/RCE detection) |

Templates reference `{{interactsh-url}}`; matches arrive asynchronously, so
let the cooldown finish before killing the run.

## Output

| Flag | Meaning |
|---|---|
| `-o`, `-output` | write results to file |
| `-j`, `-jsonl` | JSONL output (one JSON object per finding). **There is no `-json` flag in v3.** |
| `-je`, `-json-export` | export all results as one JSON array file |
| `-me`, `-markdown-export` | per-finding markdown dir |
| `-se`, `-sarif-export` | SARIF file |
| `-irr`, `-include-rr` / `-omit-raw` | include/omit raw request/response in JSON output (default behavior differs per version — check `-h`) |
| `-silent` | findings only |
| `-nc`, `-no-color` | strip ANSI (always use when parsing) |
| `-stats` | periodic progress line |
| `-ms`, `-matcher-status` | include match failure status |
| `-v`, `-debug`, `-debug-req`, `-debug-resp` | verbosity / raw traffic dump |
| `-proxy` | route via proxy: `-proxy http://127.0.0.1:8080` (also socks5) |

### JSONL fields

```json
{
  "template-id": "exposed-swagger-ui",
  "template-path": ".../http/exposures/apis/exposed-swagger-ui.yaml",
  "info": {"name": "Public Swagger UI", "severity": "medium",
            "tags": ["exposure","api","swagger"]},
  "type": "http",
  "host": "https://api.example.com",
  "matched-at": "https://api.example.com/swagger/index.html",
  "extracted-results": ["/swagger/v1/swagger.json"],
  "request": "GET /swagger/index.html HTTP/1.1 ...",
  "response": "HTTP/1.1 200 OK ...",
  "curl-command": "curl -X GET ...",
  "ip": "203.0.113.10",
  "timestamp": "..."
}
```

Severity lives at `info.severity` (some builds mirror it top-level).
`matched-at` is the verification URL; `matcher-name` (if present)
distinguishes sub-matchers; `extracted-results` carries extractor output
(leaked keys, versions, discovered paths). `request`/`response` feed the
`http_exchange` evidence block after verification.

## Performance / reliability

| Flag | Default | Meaning |
|---|---|---|
| `-rl`, `-rate-limit` | 150 | max requests/second |
| `-rlm`, `-rate-limit-minute` | — | per-minute alternative |
| `-c`, `-concurrency` | 25 | parallel templates |
| `-bs`, `-bulk-size` | 25 | hosts processed in parallel per template |
| `-timeout` | 10 | seconds per request |
| `-retries` | 1 | retry count |
| `-mhe`, `-max-host-error` | 30 | skip host after N errors |
| `-nmhe`, `-no-mhe` | — | never skip hosts on error |
| `-rsr`, `-response-size-read` | — | cap response bytes read |
| `-sresp`, `-store-resp` | — | store all request/responses to disk |
| `-srd`, `-store-resp-dir` | `output` | directory for stored traffic |

Headless templates (some API consoles need JS): `-headless`, `-sb` show
browser, `-sc` system-chrome. Enable only when a template requires it.
