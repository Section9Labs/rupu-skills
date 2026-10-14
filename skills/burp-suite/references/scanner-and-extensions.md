# Scanner (Pro) and extensions

## Launching scans

- **Dashboard → New scan**: choose "Crawl and audit" or "Crawl" only; enter
  URLs; the Scope step auto-derives include rules (edit to pin protocol/path).
- **From the site map / proxy history**: right-click → Scan (that item or the
  whole branch). Scanning a single captured request audits exactly that
  request's insertion points — the fastest way to deep-test one endpoint.
- **Live tasks**: Dashboard → New live task → "Live audit from Proxy" (and
  "Live passive crawl"). Passive-only live audit is zero-risk free coverage
  while you browse; active live audit tests everything you touch.

## Scan configurations

Scans accept a stack of **named configurations** (later entries override
earlier). Built-ins you will actually use:

| Config | Use |
|---|---|
| `Audit checks - passive` | No attack traffic; headers, info leaks, TLS |
| `Audit checks - light active` | Fast active set, low request volume — default for CI |
| `Audit checks - medium active` | Balanced default for manual engagements |
| `Audit checks - all except time-based detection methods` | Full depth minus slow time blinds |
| `Audit coverage - maximum` | Everything; slow; use on short target lists |
| `Crawl strategy - fastest` / `- most complete` | Trade crawl depth for time |
| `Never stop crawl due to application errors` | Flaky targets |

Custom configs: Burp menu → Settings → create under Scan configurations; tune
insertion points (URL/body/cookie/header), audit optimization
(speed vs thoroughness), handling of frequently-occurring/static items, crawl
limits (max link depth, max unique locations), and per-check enablement.
Export the config JSON — the same JSON is what `--config-file=` consumes
headless and what good REST-API hygiene references by name.

## Authentication

- **Application login (username/password)**: scan launcher → Application
  login → add credentials; the crawler self-locates login forms and
  self-registers if allowed.
- **Recorded login sequence**: for multi-step/JS/SSO logins — install the
  "Burp Suite Navigation Recorder" browser extension, record the login, paste
  the exported JSON into the scan's Application login → Recorded login.
- **Platform auth** (Basic/NTLM/digest): Settings → Network → HTTP →
  Platform authentication, per destination host.
- Session handling rules (Settings → Sessions) + a macro that re-logs-in when
  a "logged out" pattern matches keep long audits authenticated; verify the
  session-validity check regex against a real logged-out response.

## Triage

Issues tab per scan task (or Target → issue view, Pro):
- **Severity** (High/Medium/Low/Info) × **Confidence** (Certain/Firm/
  Tentative). Triage order: High-Certain → High-Firm → Medium-Certain →
  everything Tentative last (Tentative = scanner saw a weak signal; must be
  manually proven).
- Each issue carries the advisory, the exact request(s)/response(s), and
  highlighted evidence. **Always replay the attached request in Repeater**
  (right-click → Send to Repeater) and confirm the behavior before filing.
- Mass-dedupe: identical issue type across many parameterized URLs is usually
  one root cause — report once with an affected-locations list, but mark every
  affected route as a `web:route` asset.
- Export: right-click issues → Report selected issues → **XML with base64
  requests/responses** → feed `scripts/parse_burp_xml.py`. Or pull via REST
  API (`scripts/burp_scan.py`).

## Must-have BApps (Extensions → BApp Store)

| BApp | What it does / when |
|---|---|
| **Logger++** | Full searchable log of every request from every tool incl. extensions; filter grammar + export CSV/JSON. Install first. |
| **Param Miner** | Guesses hidden params/headers via response diffing; finds cache-poisoning vectors (`X-Forwarded-Host` etc.). Right-click → Guess params/headers. |
| **Turbo Intruder** | Python-scripted high-speed request engine; the tool for race conditions (single-packet attack via `engine=Engine.BURP2`, `gate='race1'`) and large brute force on Community. |
| **Autorize** | Replays every proxied request with a second (low-priv/no-auth) session and diffs — systematic IDOR/privilege-escalation detection. Set the low-priv cookie, browse as admin, read the red/green table. |
| **JWT Editor** | Decode/edit/re-sign JWTs; attacks: alg=none, HS256 key confusion with the RS256 public key, embedded JWK, kid traversal. Adds a JSON Web Token tab in message editors. |
| **Active Scan++** | Extra scanner checks: host-header attacks, edge-case XML/serialization, cache poisoning probes. |
| **Collaborator Everywhere** | Injects Collaborator payloads into headers of all proxied in-scope traffic; pingbacks reveal blind SSRF/log processors. |
| **Upload Scanner** | Exhaustive file-upload testing: polyglots, extension/content-type permutations, image parser payloads (ImageTragick), re-download verification. |
| **HTTP Request Smuggler** | CL.TE/TE.CL/TE.TE/h2 desync detection and exploitation helper; pairs with the "smuggle probe" scanner checks. |
| **Hackvertor** | Tag-based nested encoding in any editor: `<@base64><@urlencode>payload<@/urlencode><@/base64>` — beats manual Decoder chains inside Intruder payloads. |

Jython/JRuby extensions need the standalone jython/jruby jar configured under
Settings → Extensions. New development should target Montoya (Java/Kotlin).

## Montoya API extension sketch

Montoya is the current extension API (legacy `IBurpExtender` is deprecated).
Minimal extension that tags every outgoing request and flags interesting
responses:

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;

public class Tagger implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("s9-tagger");
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
                // mutate every request Burp sends (any tool)
                return RequestToBeSentAction.continueWith(
                    req.withAddedHeader("X-Assess-Id", "s9-engagement"));
            }
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
                if (resp.bodyToString().contains("stack trace")) {
                    api.logging().logToOutput("ERRH candidate: "
                        + resp.initiatingRequest().url());
                }
                return ResponseReceivedAction.continueWith(resp);
            }
        });
    }
}
```

Build: depend on `net.portswigger.burp.extensions:montoya-api`, package a fat
jar, load via Extensions → Add → Java. Other useful registration points:
`api.scanner().registerScanCheck(...)` (custom active/passive checks that
surface as native issues), `api.proxy().registerRequestHandler(...)`
(proxy-only interception), `api.userInterface().registerContextMenuItemsProvider(...)`.

## rupu wiring

- Scanner issue list → `scripts/burp_scan.py` / `scripts/parse_burp_xml.py`
  → normalized JSON + `--work-units` + `--findings` payloads. Hand units to
  the `work-units` skill; file confirmed issues with the `finding-report`
  skill.
- Autorize/Param Miner hits are findings-grade only after Repeater
  confirmation; then `findings.report` with both request/response pairs
  (original + replayed) in evidence. Shapes: `references/rupu.md`.
