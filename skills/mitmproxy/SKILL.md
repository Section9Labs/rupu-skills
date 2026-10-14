---
name: mitmproxy
description: Intercept, inspect, modify, capture, and replay HTTP(S)/WebSocket traffic with mitmproxy/mitmdump/mitmweb — including browsers, mobile apps, thick clients, and non-browser HTTP clients — and automate request/response rewriting with Python addons; use it to see or tamper with live traffic, bulk-capture an app's API surface for downstream testing, or run scripted traffic mutation inside a pipeline.
license: Apache-2.0
compatibility: Requires mitmproxy >= 10 (mitmproxy, mitmdump, mitmweb on PATH); Python 3 for helper scripts.
metadata:
  author: Section9Labs
---

# mitmproxy — interception, scripted modification, and replay engine

mitmproxy is the traffic layer of the assessment: everything the client sends and the
server returns passes through it, can be edited in-flight, saved, mutated by Python
addons, and replayed. Use this skill whenever you need to (a) observe or tamper with
HTTP(S)/WS traffic, (b) harvest an application's full API surface from real usage,
(c) programmatically rewrite traffic (auth header injection, response patching,
parameter fuzzing), or (d) convert captured flows into inputs for sqlmap/dalfox/ffuf
and rupu work units.

Flag depth lives in `references/modes-and-capture.md` (front-ends, modes, CA, filters,
save/replay) and `references/addons.md` (hook API, worked addons). rupu wiring is in
`references/rupu.md`.

## 1. Pick a front-end

All three share the same proxy core, flags, and addon API. Default listen is `:8080`
(`--listen-host 0.0.0.0 --listen-port 8081` to change).

| Tool | Use when |
|---|---|
| `mitmproxy` | Interactive TUI — manual triage, intercept/edit/replay single flows. |
| `mitmdump` | Headless, tcpdump-style — pipelines, long captures, addon automation, CI. |
| `mitmweb` | Browser UI on `http://127.0.0.1:8081` — demos, flow diffing, sharing a view. |

## 2. Get TLS working

1. Start the proxy, point the client at it, browse to `http://mitm.it` **through the
   proxy** — it serves per-platform CA installers (Windows/macOS/Linux/Android/iOS).
   Cert files also live in `~/.mitmproxy/` (`mitmproxy-ca-cert.pem` / `.cer` / `.p12`).
2. Android >= 7 ignores user CAs for most apps: push the CA to the system store on a
   rooted device/emulator, or patch the APK's network security config, or hook pinning
   out with Frida/objection. iOS: install profile then toggle full trust in
   Settings → General → About → Certificate Trust Settings.
3. Certificate pinning that survives CA install shows up as client-side TLS failures
   in mitmproxy's event log (`E` in the TUI) — that is your signal to unpin.
4. `--ssl-insecure` makes mitmproxy accept invalid **upstream** certs (self-signed
   staging servers). `--ignore-hosts '^(.+\.)?example\.net:443$'` passes pinned or
   out-of-interest hosts through untouched so the rest of the app keeps working.

## 3. Choose the proxy mode (`--mode`)

- `regular` (default) — client honors proxy settings. Browsers, curl
  (`http_proxy=http://192.0.2.10:8080 https_proxy=...`), well-behaved SDKs.
- `transparent` — client is unaware; you are the gateway/router and redirect
  80/443 with iptables/pf. For devices and apps that ignore proxy settings.
- `reverse:https://example.com@443` — mitmproxy *is* the server; point the client
  (or its hosts file/DNS) at mitmproxy, which forwards to the real origin. Ideal for
  thick clients with a hardcoded API host and for exposing one app through the proxy.
- `upstream:http://198.51.100.5:8081` — chain through another proxy (Burp, corporate
  egress) while still scripting in mitmproxy.
- `socks5` — clients that only speak SOCKS.
- `local` — intercept a *local process* by name/PID without any network plumbing:
  `mitmproxy --mode local:curl` or `--mode local` for everything. Best option for
  thick clients on the same box.
- `wireguard` — mitmproxy runs a WireGuard server; install the printed config in the
  official WireGuard app on a phone. The cleanest mobile capture path: no root, no
  gateway tricks (CA install still required for TLS).

Modes compose: `--mode regular --mode wireguard` serves both at once.

## 4. Interactive triage (mitmproxy TUI)

Flow list → arrows/`j`/`k` to move, `Enter` to open a flow, `Tab` between
request/response, `q` back, `?` help, `z` clear list.

- **Scope the view**: `f` sets a view filter, e.g. `~d example\.com & ~m POST`.
  Filter language (full table in `references/modes-and-capture.md`): `~u <re>` URL,
  `~d <re>` domain, `~m <re>` method, `~q` has-no-response (request-only), `~s` has
  response, `~c 302` status code, `~h <re>` header, `~b <re>` body, `~bq`/`~bs`
  request/response body, combinators `& | ! ( )`.
- **Intercept**: `i` then a filter (`~q & ~d example\.com` catches requests before
  they leave). Intercepted flows show red; `a` resumes one, `A` resumes all.
- **Edit**: on an intercepted (or any) flow, `e` → choose part (path, query, header,
  body, method, status) → edit in the built-in editor or `$EDITOR`.
- **Replay**: `r` client-replays the selected request (hits the server again — edit
  then `r` is the fast manual repeater loop). `S` sets up server replay from saved
  flows (serve recorded responses instead of contacting the server).
- **Export**: `E` exports a flow as raw HTTP / curl / httpie — the raw export is
  exactly what `sqlmap -r` and manual tampering want.
- `b` saves a response body to a file; `w` writes flows to a file; `d` deletes;
  `D` duplicates (duplicate → edit → replay keeps the original intact).

## 5. Capture, replay, offline processing (mitmdump)

```sh
# Capture everything to a flow file (prefix + appends instead of truncating)
mitmdump -w capture.mitm
mitmdump -w +capture.mitm "~d example\.com"      # trailing positional arg = filter

# Offline: -n = don't bind a proxy, -r = read a flow file.
# Subset a capture: read, filter, rewrite
mitmdump -nr capture.mitm -w api-only.mitm "~d api\.example\.com & !~u \.(png|css|js)$"

# Re-run saved requests against the live server (client replay)
mitmdump -nC api-only.mitm -w replayed.mitm

# Run an addon over a capture offline (no network at all)
mitmdump -nr capture.mitm -s scripts/harvest_addon.py --set harvest_file=api.jsonl
```

`--set key=value` tunes any option: `--set flow_detail=3` (dump verbosity),
`--set view_filter='~d example\.com'`, `--set save_stream_file=+log.mitm`,
`--set connection_strategy=lazy`. `mitmdump --options` lists them all.

## 6. Addons — the core power

`-s addon.py` loads a script (hot-reloaded on save, so you can edit while traffic
runs). Hooks receive a `flow: mitmproxy.http.HTTPFlow`; mutate
`flow.request.{method,url,host,path,headers,query,urlencoded_form,content,text}` and
`flow.response.{status_code,headers,content,text}`. Key hooks: `request`,
`requestheaders`, `response`, `responseheaders`, `websocket_message`, `tcp_message`,
lifecycle `load(loader)` / `configure(updates)` / `done()`. Expose classes via
`addons = [MyAddon()]`; log with `ctx.log.info(...)`.

Thirty-second examples (full worked versions in `references/addons.md`):

```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    flow.request.headers["Authorization"] = "Bearer eyJ..."   # inject on every request

def response(flow: http.HTTPFlow) -> None:
    if flow.response and "application/json" in flow.response.headers.get("content-type", ""):
        flow.response.text = flow.response.text.replace('"premium":false', '"premium":true')
```

Run: `mitmdump -s inject.py "~d api\.example\.com"`. See `references/addons.md` for:
header strip/inject, body rewrite, endpoint+parameter logger, duplicate-and-mutate
parameter fuzzer, flow tagger with `flow.marked`/metadata, and defining custom
options settable via `--set`.

## 7. Harvest the API surface → rupu (parse/handoff step)

This is the standard bulk-capture pipeline:

```sh
# 1. Record real usage (browser session, mobile app walk, thick client exercise)
mitmdump --mode wireguard -s scripts/harvest_addon.py \
  --set harvest_file=harvest.jsonl -w capture.mitm

# 2. Normalize into endpoint records + rupu outputs (pure stdlib, offline)
python3 scripts/flows_to_targets.py harvest.jsonl \
  -o endpoints.json --work-units wu.json --assets assets.json --depth crawled
```

`flows_to_targets.py` also accepts HAR files (mitmweb export / browser DevTools) and
plain newline URL lists; mix multiple inputs on the command line. It deduplicates by
method+host+path+param-set and emits:

- `endpoints.json` — normalized `{method,url,host,path,params}` records,
- `wu.json` — a work-units JSON array (first char `[`) for `for_each:`/dispatch —
  hand it to the `work-units` skill to normalize/split further,
- `assets.json` — ready-made `assets.mark` payloads (`web:site`, `web:route`) —
  record them per the `coverage-assets` skill, depth `mapped` (probed) or `crawled`
  (walked via real usage).

**Every parse/handoff step here ends in rupu output**: work-units array, `assets.mark`
calls, or `findings.report`. Exact JSON shapes: `references/rupu.md`.

## 8. Hand off to the vuln tools

- **sqlmap**: export the flow as raw HTTP (TUI `E` → raw, or `mitmdump -nr capture.mitm
  --set flow_detail=4 "~u /login"` and copy), save as `req.txt`, then
  `sqlmap -r req.txt --force-ssl --batch --level=3 --risk=2`.
- **dalfox**: feed harvested URLs-with-params:
  `python3 scripts/flows_to_targets.py harvest.jsonl --urls urls.txt` then
  `dalfox file urls.txt -o dalfox.jsonl -f jsonl`.
- **ffuf/feroxbuster**: use `endpoints.json` hosts/paths as seed wordlists; replay
  interesting flows through `-x http://127.0.0.1:8080` to keep capturing.
- **Burp/ZAP chaining**: `--mode upstream:http://127.0.0.1:8080` from Burp (or point
  ZAP's outbound proxy at mitmdump) so scanner traffic is scripted/recorded too.
- **Tampering findings** (auth bypass via header strip, price manipulation via body
  rewrite, response-based feature unlock): confirm by replaying the mutated flow,
  capture the request/response pair from the flow file, and record via the
  `finding-report` skill / `findings.report` — scope `endpoint`, `target_ref` the URL,
  evidence containing the HTTP exchange, classified by WSTG/CWE (shapes in
  `references/rupu.md`).

## Quick reference

```sh
mitmproxy                                      # TUI on :8080
mitmweb --listen-port 8080 --web-port 8081     # browser UI
mitmdump -w +cap.mitm "~d example\.com"        # filtered capture, append
mitmdump -nr cap.mitm -w sub.mitm "~m POST"    # offline subset
mitmdump -nC sub.mitm                          # client-replay a capture
mitmdump -s addon.py --ssl-insecure            # scripted MITM, lax upstream TLS
mitmproxy --mode local:myclient                # intercept one local process
mitmdump --mode reverse:https://example.com@443 --listen-port 443
mitmdump --mode wireguard                      # mobile capture, no root routing
```
