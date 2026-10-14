# ZAP daemon mode + REST API reference

## Starting the daemon

```sh
zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=SECRETKEY
```

Useful extra `-config` keys (all settable at startup or later via
`/JSON/core/action/setOption.../`):

| Config | Purpose |
|---|---|
| `api.key=KEY` | require this key on every API call (query `apikey=` or header `X-ZAP-API-Key`) |
| `api.addrs.addr.name=.*` + `api.addrs.addr.regex=true` | accept API clients from any address (default is localhost only) |
| `api.disablekey=true` | no key (local throwaway containers only) |
| `connection.timeoutInSecs=60` | outbound timeout |
| `network.connection.httpProxy.*` | upstream proxy chain (e.g. through Burp) |
| `database.recoverylog=false` | faster for large scans |

Other launch flags: `-port`/`-host` (proxy listen), `-newsession /path/s1` or
`-session /path/s1` (persist/reopen a session file), `-dir /path` (alternate
home), `-addoninstall <id>` / `-addonupdate`, `-silent` (no update checks),
`-cmd` (inline command mode, used with `-autorun`), `-config k=v` (repeatable),
`-configfile file.properties`.

Headless on a server: `Xvfb` is NOT needed for `-daemon`/`-cmd`; the AJAX
spider does need a browser (`firefox-esr`/`chromium` present, or use the
Docker image which bundles one).

## API URL pattern

```
http://<zaphost>:<port>/<FORMAT>/<component>/<kind>/<name>/?apikey=KEY&param=value
```

- `FORMAT`: `JSON`, `XML`, `HTML` (human), or `OTHER` (raw bytes — reports,
  CA cert, HAR).
- `kind`: `view` (read state), `action` (do something), `other` (raw output).
- Through the proxy itself, the magic hostname `http://zap/` reaches the API.
- API catalog is self-documenting: browse `http://127.0.0.1:8090/UI/` for
  every component/view/action with parameter forms.
- URL-encode all parameter values (`scanPolicyName=Default%20Policy`).

## Worked curl sequences

Environment used below:

```sh
Z=http://127.0.0.1:8090; K=SECRETKEY; T=https://app.example.com
zq() { curl -s "$Z/JSON/$1/?apikey=$K&$2"; }   # tiny helper
```

### Seed + traditional spider

```sh
zq core/action/accessUrl "url=$T"                       # seed the Sites tree
zq spider/action/scan "url=$T&recurse=true&maxChildren=0&subtreeOnly=true"
# -> {"scan":"3"}
while [ "$(zq spider/view/status 'scanId=3' | sed 's/[^0-9]//g')" != "100" ]; do sleep 2; done
zq spider/view/results "scanId=3"                       # URLs found
zq core/view/urls "baseurl=$T"                          # everything known
```

### AJAX spider (SPAs)

```sh
zq ajaxSpider/action/scan "url=$T&inScope=false&subtreeOnly=true"
until zq ajaxSpider/view/status "" | grep -q stopped; do sleep 5; done
zq ajaxSpider/view/numberOfResults ""
```

### Wait for the passive scanner

Passive rules run on a queue; drain it before reading alerts:

```sh
until [ "$(zq pscan/view/recordsToScan '' | sed 's/[^0-9]//g')" = "0" ]; do sleep 2; done
```

### Active scan

```sh
zq ascan/action/scan "url=$T&recurse=true&inScopeOnly=false&scanPolicyName=Default%20Policy"
# -> {"scan":"1"}
while [ "$(zq ascan/view/status 'scanId=1' | sed 's/[^0-9]//g')" != "100" ]; do sleep 5; done
zq ascan/view/scanProgress "scanId=1"      # per-plugin progress/req counts
zq ascan/view/alertsIds "scanId=1"
```

Scan policy tuning: `ascan/action/{enableAllScanners,disableAllScanners}`,
`ascan/action/setScannerAttackStrength "id=40018&attackStrength=HIGH"`,
`ascan/action/setScannerAlertThreshold "id=40018&alertThreshold=LOW"`,
`ascan/view/scanners "scanPolicyName=..."` to list plugin ids.

### Alerts + reports

```sh
zq core/view/numberOfAlerts "baseurl=$T"
zq core/view/alerts "baseurl=$T&start=0&count=500"       # paginate start+=500
zq alert/view/alertsSummary "baseurl=$T"                 # counts by risk
curl -s "$Z/OTHER/core/other/jsonreport/?apikey=$K" -o report.json
curl -s "$Z/OTHER/core/other/htmlreport/?apikey=$K" -o report.html
# templated reports (reports add-on):
zq reports/action/generate "title=Scan&template=traditional-json&reportDir=%2Ftmp&reportFileName=report.json"
```

Alert JSON fields per element of `alerts`: `alert`/`name`, `risk`,
`confidence`, `url`, `param`, `method`, `attack`, `evidence`, `cweid`,
`wascid`, `pluginId`, `alertRef`, `description`, `solution`, `other`,
`messageId` (fetch the full exchange with
`zq core/view/message "id=<messageId>"` — gives requestHeader/requestBody/
responseHeader/responseBody for findings evidence).

### Authenticated scanning via the API

```sh
# 1. context
zq context/action/newContext "contextName=app"                    # -> contextId
zq context/action/includeInContext "contextName=app&regex=https:%2F%2Fapp.example.com%2F.*"
zq context/action/excludeFromContext "contextName=app&regex=.*logout.*"
# 2. authentication method (form-based example; methodConfigParams is form-encoded-within-encoded)
zq authentication/action/setAuthenticationMethod \
  "contextId=1&authMethodName=formBasedAuthentication&authMethodConfigParams=loginUrl%3Dhttps%253A%252F%252Fapp.example.com%252Flogin%26loginRequestData%3Dusername%253D%257B%2525username%2525%257D%2526password%253D%257B%2525password%2525%257D"
zq authentication/action/setLoggedInIndicator "contextId=1&loggedInIndicatorRegex=Logout"
zq authentication/action/setLoggedOutIndicator "contextId=1&loggedOutIndicatorRegex=Login"
# json-based auth: authMethodName=jsonBasedAuthentication, same shape with a JSON body template
# 3. session management
zq sessionManagement/action/setSessionManagementMethod "contextId=1&methodName=cookieBasedSessionManagement"
# 4. user
zq users/action/newUser "contextId=1&name=alice"                  # -> userId
zq users/action/setAuthenticationCredentials \
  "contextId=1&userId=0&authCredentialsConfigParams=username%3Dalice%26password%3DS3cret%2521"
zq users/action/setUserEnabled "contextId=1&userId=0&enabled=true"
# 5. scan as the user
zq spider/action/scanAsUser "contextId=1&userId=0&url=$T&recurse=true"
zq ascan/action/scanAsUser  "contextId=1&userId=0&url=$T&recurse=true"
# optional: force every proxied request onto that user
zq forcedUser/action/setForcedUser "contextId=1&userId=0"
zq forcedUser/action/setForcedUserModeEnabled "boolean=true"
```

Simpler alternative when a bearer token/cookie is already in hand — inject it
into everything with the replacer:

```sh
zq replacer/action/addRule \
  "description=auth&enabled=true&matchType=REQ_HEADER&matchString=Authorization&replacement=Bearer%20eyJ...&initiators="
```

### Housekeeping

```sh
zq core/action/newSession "name=run2&overwrite=true"
zq spider/action/stopAllScans ""; zq ascan/action/stopAllScans ""
zq core/action/shutdown ""
```

## Python client alternative

`pip install zaproxy` (package import `zapv2`, historically
python-owasp-zap-v2.4):

```python
from zapv2 import ZAPv2
zap = ZAPv2(apikey='SECRETKEY',
             proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
sid = zap.spider.scan('https://app.example.com', recurse=True)
while int(zap.spider.status(sid)) < 100: time.sleep(2)
aid = zap.ascan.scan('https://app.example.com', recurse=True)
while int(zap.ascan.status(aid)) < 100: time.sleep(5)
alerts = zap.core.alerts(baseurl='https://app.example.com')
```

The stdlib-only equivalent (no pip) is `scripts/zap_scan.py` in this skill —
prefer it inside the fleet since it also emits the rupu outputs
(see `references/rupu.md`).
