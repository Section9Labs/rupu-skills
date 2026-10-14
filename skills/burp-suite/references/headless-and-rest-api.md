# Headless Burp and the built-in REST API (Pro)

## Headless CLI

```
java -jar -Djava.awt.headless=true burpsuite_pro.jar \
  --project-file=/opt/burp/example.burp \
  --config-file=/opt/burp/project-options.json \
  --user-config-file=/opt/burp/user-options.json \
  --unpause-spider-and-scanner \
  --disable-extensions
```

- `-Djava.awt.headless=true` — no GUI; must precede `-jar`'s class args
  (i.e. it is a JVM flag).
- `--project-file=<path>` — created if absent; **required** for persistence
  (site map, tasks, issues). Pair with `--diagnostics` to debug startup.
- `--config-file=<json>` — project-level options (scan configs, scope,
  session rules) exported from a GUI-configured project. Repeatable;
  `--user-config-file` for user-level options (REST API enablement + keys
  live here).
- `--unpause-spider-and-scanner` — **the flag that matters in CI**: tasks in
  a reopened project start paused; this auto-resumes them so a pre-staged
  scan actually runs.
- `--disable-extensions` — faster, deterministic startup for pipelines.
- `--auto-repair` — recover a dirty project file.
- Community edition cannot save project files and has no scanner — headless
  automation is effectively Pro-only.

Typical CI recipe: configure once in the GUI (scope, scan config, REST API
key), export user+project config JSON, then launch headless with those
configs and drive scans over the REST API from the pipeline job.

## REST API

### Enable
Settings → Suite → REST API: check "Service running" (default
`127.0.0.1:1337`), create an **API key** (optionally allow keyless, don't).
With a key, the base path is `http://127.0.0.1:1337/{APIKEY}/v0.1/`.
The API is **self-documenting**: browse the base URL for an interactive
reference. Current version string: `v0.1`.

The API is intentionally minimal: start a scan, poll status/issues, read
issue/metric definitions. No site-map export, no Repeater control. For a
full-featured CI API, that is Burp Suite Enterprise/DAST's REST+CI drivers.

### Endpoints

```
GET  /{key}/v0.1/                       # API description (self-doc)
GET  /{key}/v0.1/knowledge_base/issue_definitions   # all issue types (type_index -> name/description/remediation)
POST /{key}/v0.1/scan                   # start scan -> 201 + Location: .../scan/{task_id}
GET  /{key}/v0.1/scan/{task_id}         # status, metrics, issue_events
```

### Start a scan

```
curl -s -i http://127.0.0.1:1337/$KEY/v0.1/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "urls": ["https://example.com/"],
    "scan_configurations": [
      {"type": "NamedConfiguration", "name": "Audit checks - light active"},
      {"type": "CustomConfiguration", "config": "{\"crawler\":{\"crawl_limits\":{\"maximum_crawl_time\":30}}}"}
    ],
    "application_logins": [
      {"type": "UsernameAndPasswordLogin", "username": "tester", "password": "Passw0rd!"},
      {"type": "RecordedLogin", "label": "sso", "script": "<recorded-login-json>"}
    ],
    "scope": {
      "type": "SimpleScope",
      "include": [{"rule": "https://example.com"}],
      "exclude": [{"rule": "https://example.com/logout"}]
    },
    "resource_pool": "Default resource pool",
    "protocol_option": "httpAndHttps"
  }'
```

Response: `201 Created`, header `Location: /{key}/v0.1/scan/42` → task id
`42`. Scan configuration names must exist in the Burp instance (built-ins
always do). `scope` defaults to the started URLs' prefixes if omitted.

### Poll a scan

```
curl -s http://127.0.0.1:1337/$KEY/v0.1/scan/42 | python3 -m json.tool
```

Response shape (abridged):

```json
{
  "task_id": "42",
  "scan_status": "auditing",
  "scan_metrics": {
    "crawl_requests_made": 1200,
    "audit_requests_made": 45810,
    "crawl_and_audit_progress": 63,
    "issue_events": 17
  },
  "issue_events": [
    {
      "id": 3,
      "type": "issue_found",
      "issue": {
        "name": "SQL injection",
        "type_index": 1049088,
        "serial_number": "3",
        "origin": "https://example.com",
        "path": "/product?id=1",
        "severity": "high",
        "confidence": "firm",
        "description": "...",
        "evidence": [
          {
            "type": "FirstOrderEvidence",
            "detail": {"payload": {"bytes": "Jyc="}},
            "request_response": {
              "url": "https://example.com/product?id=1",
              "request":  [{"type": "DataSegment", "data": "R0VUIC9wcm9kdWN0..."},
                           {"type": "HighlightSegment", "data": "Jyc="}],
              "response": [{"type": "DataSegment", "data": "SFRUUC8xLjEgNTAw..."},
                           {"type": "SnipSegment", "length": 20480}]
            }
          }
        ]
      }
    }
  ]
}
```

Key facts for parsing:
- `scan_status`: `initializing` → `crawling` → `auditing` →
  `succeeded` | `failed` | `paused`.
- `issue_events` accumulates; dedupe on `(name, origin+path)` or
  `serial_number`.
- Request/response bodies arrive as **segment arrays**: `DataSegment` /
  `HighlightSegment` carry base64 `data`; `SnipSegment` marks `length` bytes
  omitted. Concatenate decoded segments in order to reconstruct the message.
- `severity`: `high|medium|low|info|false_positive`;
  `confidence`: `certain|firm|tentative`.
- Resolve `type_index` → canonical name/remediation via
  `knowledge_base/issue_definitions`.

### Script

`scripts/burp_scan.py` wraps all of the above (urllib only):

```
python3 scripts/burp_scan.py \
  --base-url http://127.0.0.1:1337 --api-key $KEY \
  --url https://example.com/ \
  --scan-config "Audit checks - light active" \
  --username tester --password 'Passw0rd!' \
  --include https://example.com --exclude https://example.com/logout \
  --poll-interval 15 --timeout 7200 \
  -o burp-issues.json --work-units burp-units.json --findings burp-findings.json
```

Env fallbacks: `BURP_API_URL`, `BURP_API_KEY`. Add `--no-wait` to start and
print the task id only; `--task-id N` to resume polling an existing task.

## XML export path (no REST API / Community triage of Pro exports)

GUI: select issues → right-click → "Report selected issues" → format **XML**,
check "Include requests/responses" (base64). Structure:

```xml
<issues burpVersion="2024.x">
  <issue>
    <serialNumber>527...</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="203.0.113.10">https://example.com</host>
    <path><![CDATA[/product]]></path>
    <location><![CDATA[/product [id parameter]]]></location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueBackground>...</issueBackground>
    <issueDetail>...</issueDetail>
    <requestresponse>
      <request method="GET" base64="true">R0VUIC9wcm9k...</request>
      <response base64="true">SFRUUC8xLjEg...</response>
    </requestresponse>
  </issue>
</issues>
```

Parse with:

```
python3 scripts/parse_burp_xml.py burp-export.xml \
  -o burp-issues.json --work-units burp-units.json --findings burp-findings.json
```

Both scripts emit identical normalized structures, so downstream rupu wiring
(`references/rupu.md`) does not care which path produced them.
