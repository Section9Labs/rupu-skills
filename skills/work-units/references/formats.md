# Source formats: fields, producing commands, and the target/hint mapping

Per-kind depth for `scripts/split.py`. Field names below are the current
machine formats as the tools actually emit them. Examples use documentation
addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, example.com).

---

## nmap (`split.py nmap`)

**Produce it:**

```sh
nmap -sV -sC -p- -T4 -oX reports/scan.xml 203.0.113.0/24
# UDP too:
nmap -sU -sV --top-ports 100 -oX reports/udp.xml 203.0.113.20
```

Always `-oX` (XML). Normal output (`-oN`) and grepable (`-oG`) are not parsed.
`-sV` fills `product`/`version`; `-sC` (or `--script`) fills `<script>` nodes.

**XML structure consumed:**

```
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="203.0.113.20" addrtype="ipv4"/>   <!-- ipv4|ipv6|mac -->
    <hostnames><hostname name="example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open" .../>                     <!-- only "open" kept -->
        <service name="https" product="nginx" version="1.18.0"
                 extrainfo="Ubuntu" tunnel="ssl" method="probed" conf="10"/>
        <script id="http-title" output="Login — example.com"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

**Mapping:**

| XML                              | work unit                                   |
|----------------------------------|---------------------------------------------|
| `address@addr` (ipv4/ipv6)       | target `{type: host}` + identity key        |
| `port@portid`, `port@protocol`   | target `{type: service, host, port, protocol}` + identity |
| `service@name/product/version/extrainfo/tunnel` | hints `service/product/version/extrainfo/tunnel` |
| `hostnames/hostname@name`        | hint `hostname`                             |
| `script@id`, `script@output`     | hint `scripts` (map id → output, trimmed to 400 chars) |

Down-host entries (`<status state="down">`) and non-open ports are skipped.
Identity: `service|<addr>|<port>|<proto>` — the same key naabu uses, so merge
collapses them. `--group-by-host` instead builds `host|<addr>` units whose
targets list every open service and whose hints carry a `services` summary.

---

## naabu (`split.py naabu`)

**Produce it:**

```sh
naabu -host example.com -top-ports 1000 -json -silent -o reports/ports.jsonl
naabu -list hosts.txt -p 1-65535 -json -silent -o reports/ports.jsonl
```

`-json` emits JSONL, one object per open port:

```json
{"host":"example.com","ip":"203.0.113.20","port":8443,"protocol":"tcp","tls":true,"timestamp":"2024-05-01T10:00:00Z"}
```

Older naabu releases nested the port: `"port":{"Port":8443,"Protocol":"tcp"}` —
the splitter handles both.

**Mapping:** `ip` (fallback `host`) → host target and identity; `port`+`protocol`
→ service target; `host` (when it is a DNS name different from `ip`) → hint
`hostname`; `tls` → hint `tls`. Identity: `service|<ip>|<port>|<proto>`.

---

## httpx (`split.py httpx`)

**Produce it:**

```sh
httpx -l hosts.txt -json -silent -title -tech-detect -status-code \
      -web-server -follow-redirects -o reports/web.jsonl
# straight from naabu:
naabu -list hosts.txt -json -silent | httpx -json -silent -o reports/web.jsonl
```

JSONL, one object per responding URL. Key fields (projectdiscovery httpx):

```json
{"timestamp":"...","url":"https://example.com:8443/admin","input":"example.com",
 "scheme":"https","host":"203.0.113.20","port":"8443","path":"/admin",
 "status_code":200,"title":"Admin Console","webserver":"nginx/1.18.0",
 "tech":["Nginx:1.18.0","PHP"],"content_type":"text/html","content_length":4213,
 "a":["203.0.113.20"],"cname":["edge.example.com"],"location":"",
 "final_url":"https://example.com:8443/admin/login","cdn_name":"","failed":false}
```

**Mapping:**

| httpx field                        | work unit                              |
|------------------------------------|----------------------------------------|
| `url`                              | target `{type: url}` + identity (`url|<url>`) |
| `host`, `port`                     | targets `{type: host}` and `{type: service}` |
| `scheme`,`status_code`,`title`,`webserver`,`tech`,`content_type`,`content_length`,`location`,`final_url` | same-named hints |
| `a`, `cname`                       | hints `ips`, `cnames`                  |
| `input`                            | hint `input` (the probed seed — useful raw reference) |

Note `port` is a **string** in httpx JSON; the splitter casts it. Title format:
`https://example.com:8443/admin [200] 'Admin Console' (nginx/1.18.0)`.

---

## OpenAPI 3 / Swagger 2 (`split.py openapi`)

Input must be **JSON**. The Python stdlib has no YAML parser — if the spec is
YAML, fetch the JSON variant (`/openapi.json`, `/v2/swagger.json`,
`/v3/api-docs`) or convert it before splitting.

**Base URL resolution** (overridable with `--base-url`):

- OAS 3: `servers[0].url`
- Swagger 2: `schemes[0] + "://" + host + basePath`

**One unit per (path, method)** across methods
`get post put patch delete head options trace`. Path-level `parameters` are
merged into every operation under that path.

| spec field                               | work unit                                |
|------------------------------------------|------------------------------------------|
| `base + path`                            | target `{type: url}`                     |
| method + path                            | target `{type: http_route, method, path}` + identity `route|METHOD|path|base` |
| `operationId`                            | hint `operation_id`                      |
| `summary`, `tags`                        | hints `summary`, `tags`                  |
| `security` (operation, else document)    | hint `security`; `security: []` → hint `unauthenticated: true` (explicitly open endpoint — prime fuzz target) |
| `parameters` (name/in/required, `$ref`s kept as refs) | hint `parameters` |
| OAS3 `requestBody.content` keys          | hint `request_body_types`                |
| Swagger 2 `consumes`                     | hint `consumes`                          |
| `deprecated: true`                       | hint `deprecated` (often forgotten, weakly maintained code paths) |

Title: `POST /api/v2/orders — example.com`.

---

## SARIF 2.1.0 (`split.py sarif`)

**Produce it:** any SARIF-emitting scanner, e.g.
`semgrep scan --config auto --sarif -o reports/semgrep.sarif`,
CodeQL `database analyze ... --format=sarif-latest`,
`trivy fs --format sarif -o reports/trivy.sarif .`.

**Structure consumed:**

```
runs[].tool.driver.name                      -> hint tool
runs[].tool.driver.rules[]                   -> rule lookup table
  .id, .name
  .defaultConfiguration.level
  .properties.tags[]                         -> hint tags; CWE-\d+ extracted -> hint cwe
  .properties."security-severity"            -> hint security_severity
runs[].results[]
  .ruleId (or .ruleIndex into rules[])       -> hint rule_id + identity
  .level                                     -> hint level (fallback: rule default, then "warning")
  .message.text                              -> hint message (trimmed 500)
  .partialFingerprints                       -> hint fingerprints (stable cross-run keys)
  .locations[].physicalLocation
     .artifactLocation.uri                   -> target {type: file, value}
     .region.startLine/endLine/startColumn   -> target start_line/end_line/start_column
     .region.snippet.text                    -> target snippet (trimmed 200)
```

One unit per `results[]` entry. Identity:
`code|<ruleId>|<first uri>|<startLine>|<startColumn>` — stable across re-scans
of the same tree. Title: `js/sql-injection — src/db.js:42`.

---

## Prowler OCSF (`split.py prowler`)

**Produce it:**

```sh
prowler aws -M json-ocsf --output-filename prowler --output-directory reports
# also: prowler azure / gcp / kubernetes -M json-ocsf
```

Prowler writes an OCSF **Detection Finding** array (older builds emit JSONL);
the splitter accepts both. Fields consumed per finding:

```
metadata.event_code            -> hint check_id        (e.g. "s3_bucket_public_access")
finding_info.uid               -> identity (finding|<uid>) + hint finding_uid
finding_info.title             -> hint check_title / title
finding_info.types[]           -> hint types
status_code                    -> hint status           ("FAIL" | "PASS"; --fail-only filters)
status_detail                  -> hint status_detail
severity                       -> hint severity         ("Critical".."Informational")
cloud.provider                 -> hint provider         ("aws"/"azure"/"gcp"/...)
cloud.account.uid              -> hint account
cloud.region                   -> hint region
resources[].uid                -> target {type: cloud_resource, value}  (ARN etc.)
resources[].name/.type/.region -> target name/resource_type/region
unmapped.compliance            -> hint compliance       (framework -> controls map)
unmapped.related_url           -> hint related_url
remediation.desc               -> hint remediation (trimmed 300)
risk_details                   -> hint risk (trimmed 300)
```

One unit per finding. Title: `<finding_info.title> — <first resource name>`.
If `finding_info.uid` is absent, identity falls back to
`finding|<check_id>|<first resource uid>`.

---

## Generic JSON (`split.py json`)

For any tool the fleet has not special-cased, as long as it emits a JSON array
of objects or JSONL. Default field probing, overridable per flag:

| role    | flag             | default probe order                                |
|---------|------------------|----------------------------------------------------|
| id      | `--id-field`     | `id`, `uid`, `key`, `name`                         |
| title   | `--title-field`  | `title`, `name`, `summary`, `message`, `description` |
| targets | `--target-field` | `targets`, `target`, `url`, `host`, `ip`, `endpoint`, `asset`, `path` |

Target field name picks the target type (`url`→url, `host`/`ip`/`asset`→host,
`path`→file, else `target`). Lists become multiple targets; dicts with a
`value` key pass through with their extra keys preserved. **Every field not
consumed as id/title/target lands in `hints` verbatim**, so nothing the tool
said is lost. If no id field exists, the identity is a sha1 over the
sort-keyed record — still deterministic across re-runs over the same input.

Example — a custom fuzzer's JSONL:

```sh
python3 scripts/split.py json fuzz.jsonl \
  --id-field vuln_id --title-field name --target-field endpoint \
  -o reports/fuzz-units.json
```

---

## Identity keys at a glance (what merge.py dedups on)

| unit kind      | identity string                                  | emitted by kinds |
|----------------|--------------------------------------------------|------------------|
| service        | `service\|host\|port\|proto`                     | nmap, naabu, httpx (secondary target) |
| host           | `host\|addr`                                     | nmap `--group-by-host` |
| url            | `url\|<url>`                                     | httpx            |
| http route     | `route\|METHOD\|path\|base`                      | openapi          |
| code result    | `code\|rule\|file\|line\|col`                    | sarif            |
| cloud finding  | `finding\|<uid>`                                 | prowler          |
| generic        | `json\|<id>` or `json\|sha1(record)`             | json             |

The rendered id is `slug(identity)[:48] + "-" + sha1(identity)[:8]`, e.g.
`service-203-0-113-20-8443-tcp-9f2c41ab`. Slug-safe, globally unique, stable.
