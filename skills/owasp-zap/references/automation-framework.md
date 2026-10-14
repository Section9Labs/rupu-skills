# ZAP Automation Framework reference

Run: `zap.sh -cmd -autorun /abs/path/plan.yaml` (add `-addoninstall <id>` /
`-addonupdate` as needed). Exit codes: **0** success, **1** error, **2** warn —
driven by the `exitStatus` job. In Docker:

```sh
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

Generate/edit plans in the GUI (Automation tab -> jobs have forms -> Save Plan)
then commit the YAML. Variables: `${envvar}` interpolates environment
variables anywhere in the plan — keep credentials out of the file.

## `env` section

```yaml
env:
  contexts:
    - name: app
      urls: ["https://app.example.com"]
      includePaths: ["https://app.example.com/.*"]
      excludePaths: [".*logout.*", ".*\\.(png|jpg|css|js)$"]
      authentication:            # see authenticated plan below
      sessionManagement:
      users:
  vars:                          # plan-local variables, use as ${name}
    base: https://app.example.com
  parameters:
    failOnError: true            # exit 1 on job error
    failOnWarning: false
    progressToStdout: true
```

## Jobs (ordered; each runs in sequence)

| Job | Purpose | Key parameters |
|---|---|---|
| `passiveScan-config` | tune passive rules before traffic | `maxAlertsPerRule`, `scanOnlyInScope`, `enableTags`, `rules:` (id/threshold) |
| `spider` | traditional crawl | `context`, `user`, `url`, `maxDuration` (min), `maxDepth`, `maxChildren`, `subtreeOnly` |
| `spiderAjax` | browser crawl for SPAs | `context`, `url`, `maxDuration`, `maxCrawlDepth`, `browserId` (`firefox-headless`/`chrome-headless`), `numberOfBrowsers` |
| `passiveScan-wait` | drain the passive queue | `maxDuration` |
| `activeScan` | attack everything found | `context`, `user`, `policy`, `maxRuleDurationInMins`, `maxScanDurationInMins`, `threadPerHost`; inline `policyDefinition:` with `defaultStrength`/`defaultThreshold` + per-rule `rules:` list |
| `activeScan-config` / `activeScan-policy` | global ascan opts / named policy definition | handle anti-CSRF tokens, strength/threshold maps |
| `openapi` | import an API definition | `apiFile` or `apiUrl`, `targetUrl` (override servers), `context` |
| `graphql` | import a GraphQL schema | `schemaFile`/`schemaUrl`, `endpoint`, query gen options |
| `soap` | import WSDL | `wsdlFile`/`wsdlUrl` |
| `requestor` | send hand-crafted requests (seed, login probe, health check) | `requests:` list of `{url, method, headers, data, responseCode}` |
| `replacer` | rewrite every request/response | `rules:` of `{description, matchType: REQ_HEADER..., matchString, replacementString, tokenProcessing}` — the easy way to inject `Authorization: Bearer ${TOKEN}` |
| `script` | load/run AF scripts | `action: add|run`, `type`, `engine`, `name`, `file` |
| `delay` | pause | `time` |
| `alertFilter` | reclassify/suppress alerts pre-report | `alertFilters:` of `{ruleId, newRisk, url, parameter}` |
| `report` | write a report | `template` (`traditional-json`, `traditional-html`, `traditional-xml`, `modern`, `sarif-json`, `risk-confidence-html`), `reportDir`, `reportFile`, `sites`, `risks`/`confidences` filters |
| `exitStatus` | set process exit code | `errorLevel`, `warnLevel` (risk names), `okExitValue`/`warnExitValue`/`errorExitValue` |

## Worked plan: full unauthenticated scan

```yaml
env:
  contexts:
    - name: app
      urls: ["https://app.example.com"]
      includePaths: ["https://app.example.com/.*"]
  parameters: { failOnError: true, progressToStdout: true }
jobs:
  - type: passiveScan-config
    parameters: { maxAlertsPerRule: 10, scanOnlyInScope: true }
  - type: spider
    parameters: { context: app, maxDuration: 10, maxDepth: 10 }
  - type: spiderAjax
    parameters: { context: app, maxDuration: 10, browserId: firefox-headless }
  - type: passiveScan-wait
    parameters: { maxDuration: 10 }
  - type: activeScan
    parameters: { context: app, maxScanDurationInMins: 120, threadPerHost: 4 }
    policyDefinition:
      defaultStrength: medium
      defaultThreshold: medium
      rules:
        - { id: 40018, name: SQL Injection, strength: high, threshold: low }
  - type: report
    parameters: { template: traditional-json, reportDir: /zap/wrk, reportFile: report.json }
  - type: report
    parameters: { template: traditional-html, reportDir: /zap/wrk, reportFile: report.html }
  - type: exitStatus
    parameters: { errorLevel: High, warnLevel: Medium }
```

## Worked plan: authenticated (form login + cookie session)

```yaml
env:
  contexts:
    - name: app
      urls: ["https://app.example.com"]
      includePaths: ["https://app.example.com/.*"]
      excludePaths: [".*logout.*"]
      authentication:
        method: form                 # form | json | http | script | browser | autodetect
        parameters:
          loginPageUrl: https://app.example.com/login
          loginRequestUrl: https://app.example.com/login
          loginRequestBody: "username={%username%}&password={%password%}"
        verification:
          method: poll               # response | request | both | poll | autodetect
          pollUrl: https://app.example.com/api/me
          pollFrequency: 60
          pollUnits: requests
          loggedInRegex: "\\Qalice@example.com\\E"
          loggedOutRegex: "HTTP/\\S+ 401"
      sessionManagement:
        method: cookie               # cookie | http | headers | script | autodetect
      users:
        - name: alice
          credentials: { username: alice, password: "${APP_PASSWORD}" }
  parameters: { failOnError: true, progressToStdout: true }
jobs:
  - type: spider
    parameters: { context: app, user: alice, maxDuration: 10 }
  - type: spiderAjax
    parameters: { context: app, user: alice, maxDuration: 10, browserId: firefox-headless }
  - type: passiveScan-wait
    parameters: { maxDuration: 10 }
  - type: activeScan
    parameters: { context: app, user: alice, maxScanDurationInMins: 120 }
  - type: report
    parameters: { template: traditional-json, reportDir: /zap/wrk, reportFile: report.json }
  - type: exitStatus
    parameters: { errorLevel: High, warnLevel: Medium }
```

JSON-API auth variant: `method: json` with
`loginRequestBody: '{"user":"{%username%}","pass":"{%password%}"}'` and
`sessionManagement: { method: headers, parameters: { Authorization: "Bearer {%json:token%}" } }`
(extracts `token` from the login response JSON into the header).

Token-in-hand variant (skip login entirely):

```yaml
jobs:
  - type: replacer
    rules:
      - description: bearer
        matchType: req_header
        matchString: Authorization
        replacementString: "Bearer ${TOKEN}"
```

## Worked plan: OpenAPI-driven API scan

```yaml
env:
  contexts:
    - name: api
      urls: ["https://api.example.com"]
  parameters: { failOnError: true }
jobs:
  - type: openapi
    parameters: { apiFile: /zap/wrk/openapi.json, targetUrl: "https://api.example.com", context: api }
  - type: passiveScan-wait
    parameters: { maxDuration: 5 }
  - type: activeScan
    parameters: { context: api }
  - type: report
    parameters: { template: traditional-json, reportDir: /zap/wrk, reportFile: report.json }
  - type: exitStatus
    parameters: { errorLevel: High, warnLevel: Medium }
```

## After the run

`report.json` (traditional-json) is the handoff artifact:

```sh
python3 scripts/parse_zap_report.py /zap/wrk/report.json \
  --out alerts.json --work-units wu.json --findings findings.json
```

Then follow `references/rupu.md`: mark assets, hand `wu.json` to the
`work-units` skill, and write confirmed alerts via the `finding-report` skill.
