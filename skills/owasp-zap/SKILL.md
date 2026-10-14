---
name: owasp-zap
description: Drive OWASP ZAP as the open-source DAST and interception proxy on web assessments — daemon mode + REST API, the Automation Framework (plan.yaml), and the packaged Docker scan scripts (baseline/full/api), plus interactive proxy use; produces normalized alerts, rupu work units, and findings payloads. Use for pipeline-automated scanning, authenticated/API-aware scans, and as a free interception proxy.
license: Apache-2.0
compatibility: Linux/macOS; ZAP 2.14+ (zap.sh or Docker ghcr.io/zaproxy/zaproxy:stable); Python 3.8+ for helper scripts
metadata:
  author: Section9Labs
  wstg: "WSTG-INFO through WSTG-APIT (ZAP alerts map to WSTG/CWE)"
---

# OWASP ZAP — DAST, API-driven scanning, and interception proxy

ZAP is the free workhorse DAST: a MITM proxy, a traditional + AJAX spider, a
passive scanner that flags issues from traffic alone, and an active scanner that
attacks every discovered input. Four ways to drive it — pick by context:

| Mode | When |
|---|---|
| Interactive GUI + HUD | manual testing, auth setup, exploring one app |
| Daemon + REST API | your own orchestration, fine-grained control, long-lived proxy |
| Automation Framework (`-cmd -autorun plan.yaml`) | repeatable scans, auth, CI — **preferred** |
| Packaged scripts (`zap-baseline.py` etc. in Docker) | fastest zero-config pipeline scan |

Every path ends in the same machine-readable output: ZAP **alerts** (API
`/JSON/core/view/alerts/` or a `-J report.json`). Parse them with the scripts
here and hand off per `references/rupu.md`.

## 1. Interactive basics

- **Proxy**: ZAP listens on `127.0.0.1:8080` by default. Point the browser at
  it, then install the ZAP root CA (Tools -> Options -> Network -> Server
  Certificates -> Save, or `GET http://zap/OTHER/core/other/rootcert/` through
  the proxy) into the browser trust store so HTTPS interception works. The
  "Manual Explore" launcher opens a pre-configured browser with the **HUD**
  overlaid — spider/active-scan/alerts controls directly in the page.
- **Sites tree**: everything proxied or spidered lands here. Right-click a node
  for Attack -> Spider / Active Scan, or "Open/Resend with Request Editor" for
  Repeater-style manual replays.
- **Spider vs AJAX Spider**: the traditional spider parses HTML/robots/sitemap
  fast; the **AJAX spider** drives a real browser (Firefox/Chrome via Selenium)
  and is required for SPA/JS-heavy apps. Run traditional first, AJAX second —
  the AJAX spider resumes from what the Sites tree already knows.
- **Passive vs active**: passive scanning inspects traffic as it flows (zero
  extra requests — always on). **Active scanning sends attack payloads**
  (SQLi, XSS, traversal, command injection, etc.) to every parameter: expect
  noise in logs, form submissions that create/modify data, and WAF trips —
  plan the run window accordingly and exclude destructive routes (`.*logout.*`,
  delete endpoints) from the context when you need the session/data to survive
  the scan.
- **Contexts + authentication**: define a Context (include regex
  `https://app.example.com/.*`), set Authentication (form-based / JSON / script
  / browser-based), Session Management (cookie / header), add a User, enable
  "Forced User" or scan-as-user. Verification regexes (`loggedInIndicator` /
  `loggedOutIndicator`) tell ZAP when a session died so it re-authenticates.
  Easiest auth setup: record once in the GUI, export the context, reuse it in
  the Automation Framework.

## 2. Daemon mode + the REST API

Start headless:

```sh
zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=SECRETKEY
# more throughput / remote clients:
#   -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

API URL pattern (works against the daemon host:port directly, or as the magic
host `http://zap/` when requests go **through** the proxy):

```
http://127.0.0.1:8090/<JSON|XML|HTML|OTHER>/<component>/<view|action|other>/<name>/?apikey=KEY&param=...
```

Core worked sequence (full curl detail + auth components in
`references/api-and-daemon.md`):

```sh
Z=http://127.0.0.1:8090; K=SECRETKEY; T=https://app.example.com
# spider -> poll to 100
curl -s "$Z/JSON/spider/action/scan/?apikey=$K&url=$T&recurse=true"      # {"scan":"0"}
curl -s "$Z/JSON/spider/view/status/?apikey=$K&scanId=0"                 # {"status":"100"}
# optional AJAX spider for SPAs
curl -s "$Z/JSON/ajaxSpider/action/scan/?apikey=$K&url=$T"
curl -s "$Z/JSON/ajaxSpider/view/status/?apikey=$K"                      # "running"->"stopped"
# wait for passive queue, then active scan -> poll
curl -s "$Z/JSON/pscan/view/recordsToScan/?apikey=$K"                    # wait for "0"
curl -s "$Z/JSON/ascan/action/scan/?apikey=$K&url=$T&recurse=true&scanPolicyName=Default%20Policy"
curl -s "$Z/JSON/ascan/view/status/?apikey=$K&scanId=0"
# alerts (paginated) and a full JSON report
curl -s "$Z/JSON/core/view/alerts/?apikey=$K&baseurl=$T&start=0&count=500"
curl -s "$Z/OTHER/core/other/jsonreport/?apikey=$K" -o report.json
```

Authenticated scans via the API: `context/action/newContext` ->
`context/action/includeInContext` -> `authentication/action/setAuthenticationMethod`
-> `users/action/newUser` + `setAuthenticationCredentials` + `setUserEnabled`
-> `spider/action/scanAsUser` and `ascan/action/scanAsUser` (take `contextId`
+ `userId` instead of just `url`). Exact parameter encodings in
`references/api-and-daemon.md`.

Alternative client: `pip install zaproxy` (the python-owasp-zap-v2.4 API) —
`zap = ZAPv2(apikey=K, proxies={...}); zap.spider.scan(T); zap.ascan.scan(T);
zap.core.alerts(baseurl=T)`. The stdlib-only equivalent is `scripts/zap_scan.py`:

```sh
python3 scripts/zap_scan.py --zap http://127.0.0.1:8090 --api-key SECRETKEY \
  --target https://app.example.com --ajax \
  --out alerts.json --work-units wu.json --findings findings.json
```

It spiders, polls, active-scans, pulls all alerts, normalizes them, and emits
rupu work units + findings payloads (section 6).

## 3. Automation Framework — preferred for repeatable scans

One YAML plan: `env` (contexts, URLs, users/auth, `parameters.failOnError`)
plus ordered `jobs`. Minimal full-scan plan:

```yaml
env:
  contexts:
    - name: app
      urls: ["https://app.example.com"]
      includePaths: ["https://app.example.com/.*"]
  parameters:
    failOnError: true
    progressToStdout: true
jobs:
  - type: passiveScan-config
    parameters: { maxAlertsPerRule: 10 }
  - type: spider
    parameters: { context: app, maxDuration: 10 }
  - type: spiderAjax               # JS-heavy apps only; needs a browser in the image
    parameters: { context: app, maxDuration: 10, browserId: firefox-headless }
  - type: passiveScan-wait
    parameters: { maxDuration: 10 }
  - type: activeScan
    parameters: { context: app, policy: Default Policy }
  - type: report
    parameters: { template: traditional-json, reportDir: /tmp/zap, reportFile: report.json }
  - type: exitStatus
    parameters: { errorLevel: High, warnLevel: Medium }
```

Run it:

```sh
zap.sh -cmd -autorun /abs/path/plan.yaml \
  -addoninstall reports -addonupdate
# Docker:
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml
```

Exit codes: **0** ok, **1** error, **2** warn (per the `exitStatus` job
thresholds) — wire straight into CI. Authenticated variant (users + form/JSON
auth + verification), `openapi`/`graphql` import jobs, `requestor`, `replacer`
(inject auth headers into every request), and the full per-job parameter
reference live in `references/automation-framework.md`. Generate a skeleton
from the GUI: Automation tab -> Save Plan.

Then parse the report:

```sh
python3 scripts/parse_zap_report.py /tmp/zap/report.json \
  --out alerts.json --work-units wu.json --findings findings.json
```

## 4. Packaged scan scripts (Docker)

Zero-config pipeline scans; all mount the CWD for reports:

```sh
# passive only (spider + passive rules — no attacks):
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://app.example.com -J report.json -r report.html -j -I
# spider + ACTIVE scan:
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://app.example.com -J report.json -I
# API definition scan:
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t /zap/wrk/openapi.json -f openapi -J report.json -I
```

Shared flags: `-t` target, reports `-r html -w md -x xml -J json`, `-c/-u`
rule-config file/URL (per-rule `IGNORE|INFO|WARN|FAIL`), `-I` don't fail the
exit code on WARN, `-j` add the AJAX spider, `-n ctx.context` import a saved
context (+ `-U user`), `-z "-config k=v"` pass raw ZAP configs, `-m/-T`
spider/overall time budgets, `-a` include alpha rules, `-d` debug. Exit codes:
0 pass, 1 FAIL alerts, 2 WARN (unless `-I`), 3 error. Full flag tables and
auth-header patterns in `references/packaged-scans.md`. Feed `report.json`
to `parse_zap_report.py` as above.

## 5. Custom checks — ZAP scripting (pointer)

The Scripts add-on runs JS (Graal), Jython, etc. in several hooks:
**standalone** (run on demand), **active/passive rules** (become scanner
checks that raise alerts), **httpsender** (rewrite every request — e.g.
re-sign API tokens), **authentication/session** scripts for exotic login
flows, **proxy** scripts. Manage via GUI Scripts tab or API
`/JSON/script/action/load|runStandAloneScript/`. In Automation Framework
plans the `script` job can load/run them. Use an active-rule script when a
check must appear as a first-class alert in the same reports.

## 6. Reading alerts, triage, and handoff

Each alert carries: `alert`/`name`, `risk` (High/Medium/Low/Informational),
`confidence` (High/Medium/Low/False Positive), `url`, `param`, `method`,
`attack` (payload sent), `evidence` (matched response fragment), `cweid`,
`wascid`, `pluginId`/`alertRef`, `description`, `solution`.

Triage order: **risk desc, then confidence desc**. High/High from the active
scanner (e.g. plugin 40018 SQLi, 40012/40014/40026 XSS) is usually directly
reproducible from `url`+`param`+`attack` — replay it in the Request Editor /
curl and confirm before reporting. Low-confidence or passive-only alerts
(headers, cookie flags) go straight to findings at their stated risk.
Discard "False Positive" confidence. The `attack` + `evidence` pair IS your
HTTP-exchange evidence; keep it.

Chain-out: a confirmed SQLi alert -> hand `url`+`param` to sqlmap
(`-u ... --batch`); XSS alerts -> dalfox (`dalfox scan url -p param`); each
alert group is a work unit for exactly that fan-out.

**rupu wiring (required at every parse step)** — see `references/rupu.md`
for exact JSON shapes:
- Mark the target site with `assets.mark` kind `web:site` depth `mapped` when
  the scan starts; mark each spidered URL `web:route` depth `crawled`; routes
  the active scanner attacked are `tested`; routes behind a confirmed alert
  are `exploited`.
- Both scripts emit `--work-units wu.json` — a clean JSON array (first char
  `[`) of `{id,title,targets,hints}` grouped per alert type. Hand it to the
  `work-units` skill to normalize/split, then `for_each:`/dispatch.
- Record assets per the `coverage-assets` skill; write each confirmed alert
  up via the `finding-report` skill using the `findings.report` payloads the
  scripts emit (`scope: endpoint`, `target_ref` = affected URL, severity
  mapped High->high / Medium->medium / Low->low / Informational->info,
  evidence containing the attack/evidence HTTP exchange, classification
  CWE-`cweid` plus the matching WSTG id).

## Quick reference

| Need | Command |
|---|---|
| Daemon | `zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=KEY` |
| AF plan | `zap.sh -cmd -autorun plan.yaml` (exit 0/1/2) |
| Baseline | `docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t URL -J report.json -I` |
| Full/active | `... zap-full-scan.py -t URL -J report.json -I` |
| API scan | `... zap-api-scan.py -t /zap/wrk/openapi.json -f openapi -J report.json -I` |
| Drive API | `python3 scripts/zap_scan.py --zap http://127.0.0.1:8090 --api-key KEY --target URL --out alerts.json --work-units wu.json --findings findings.json` |
| Parse report | `python3 scripts/parse_zap_report.py report.json --work-units wu.json --findings findings.json` |
