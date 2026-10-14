# mitmproxy addons — hook API and worked examples

Load with `-s addon.py` (repeatable; hot-reloaded whenever the file changes — edit
while traffic flows). Addons work identically in mitmproxy/mitmdump/mitmweb and in
offline mode (`mitmdump -nr capture.mitm -s addon.py`).

## Hook API

Module-level functions OR methods on classes listed in `addons = [...]`. The HTTP
hooks receive `flow: mitmproxy.http.HTTPFlow`.

| Hook | Fires | Notes |
|---|---|---|
| `load(loader)` | addon loaded | register options: `loader.add_option(name, type, default, help)` |
| `configure(updates)` | options changed | `updates` is a set of option names; read via `ctx.options.<name>` |
| `running()` | proxy is up | |
| `done()` | shutdown | flush files here |
| `requestheaders(flow)` | request headers read, body NOT yet | set `flow.request.stream = True` here to stream big uploads |
| `request(flow)` | full request available | mutate before it goes upstream; set `flow.response = ...` to short-circuit |
| `responseheaders(flow)` | response headers read | streaming decision point for responses |
| `response(flow)` | full response available | mutate before it returns to the client |
| `error(flow)` | flow failed | `flow.error` |
| `websocket_message(flow)` | each WS message | `flow.websocket.messages[-1]`, with `.content`, `.injected`, `.from_client`; mutate `.content` in place |
| `tcp_message(flow)` | raw TCP (non-HTTP) | `flow.messages[-1].content` |

Key objects:

```python
flow.request.method          # "GET"
flow.request.url             # full URL (settable)
flow.request.pretty_url      # honors Host header
flow.request.host, flow.request.port, flow.request.scheme, flow.request.path
flow.request.headers         # case-insensitive multidict; del/[]= work
flow.request.query           # multidict of query params (mutable)
flow.request.urlencoded_form # multidict for form bodies (mutable)
flow.request.multipart_form
flow.request.cookies
flow.request.content         # raw bytes (decoded of content-encoding)
flow.request.text            # str, decoded by charset
flow.request.json()          # parse JSON body
flow.request.raw_content     # bytes as on the wire

flow.response.status_code    # int, settable
flow.response.headers / .content / .text / .json()
flow.response = http.Response.make(200, b"body", {"Content-Type": "text/plain"})

flow.marked = ":red_circle:"       # mark (shows in UI); any emoji shorthand
flow.comment = "note"
flow.metadata["key"] = value       # addon scratch space
flow.copy()                        # duplicate a flow (for mutate-and-replay)
flow.match("~u /api/")             # evaluate a filter against the flow
flow.kill()                        # abort the flow

ctx.log.info("...") / .warn / .error
ctx.options.<name>                 # option values
ctx.master.commands.call("replay.client", [newflow])   # programmatic replay
```

Filters inside addons: `from mitmproxy import flowfilter`;
`matcher = flowfilter.parse("~d example\\.com & ~m POST")`; `matcher(flow)` → bool.

## 1. Inject / strip headers on every request

```python
"""auth_inject.py — add a bearer token, kill cache headers, strip CSP on the way back.
Run: mitmdump -s auth_inject.py '~d api\\.example\\.com'
"""
from mitmproxy import http

TOKEN = "Bearer eyJhbGciOi..."

def request(flow: http.HTTPFlow) -> None:
    flow.request.headers["Authorization"] = TOKEN
    flow.request.headers.pop("If-None-Match", None)
    flow.request.headers.pop("If-Modified-Since", None)

def response(flow: http.HTTPFlow) -> None:
    if flow.response:
        flow.response.headers.pop("Content-Security-Policy", None)
        flow.response.headers.pop("X-Frame-Options", None)
```

Testing authorization: run two mitmdump instances on different ports, one injecting
user-A's token and one user-B's, replay the same capture through both
(`mitmdump -C api.mitm --mode upstream:...` or just swap the Cookie with
`--modify-headers`), diff the responses — IDOR/broken-access-control shows up as
identical 200s where B should get 403.

## 2. Auto-rewrite a response body

```python
"""unlock.py — flip server-side feature flags client-side to test trust boundaries."""
import json
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    r = flow.response
    if not r or "application/json" not in r.headers.get("content-type", ""):
        return
    if flow.request.path.startswith("/api/v1/me"):
        try:
            body = json.loads(r.text)
        except ValueError:
            return
        body["role"] = "admin"
        body["features"] = {k: True for k in body.get("features", {})}
        r.text = json.dumps(body)
        flow.marked = ":wrench:"
```

If the client now shows admin UI and the *server* then honors the admin-only API
calls, that's a server-side authorization finding (report the server exchange, not
the client-side rewrite).

## 3. Endpoint + parameter logger (API-surface harvester)

Ship-grade version: `scripts/harvest_addon.py` (JSONL, option-configurable).
Minimal core:

```python
"""log_endpoints.py — append every endpoint + its params to a JSONL file."""
import json
from mitmproxy import http

OUT = open("endpoints.jsonl", "a", buffering=1)

def response(flow: http.HTTPFlow) -> None:
    rec = {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": flow.request.pretty_host,
        "path": flow.request.path.split("?", 1)[0],
        "query": list(flow.request.query.keys()),
        "form": list(flow.request.urlencoded_form.keys()),
        "status": flow.response.status_code if flow.response else None,
        "ctype": (flow.response.headers.get("content-type", "").split(";")[0]
                  if flow.response else None),
    }
    OUT.write(json.dumps(rec) + "\n")
```

Run during any manual walk of the app; then normalize with
`python3 scripts/flows_to_targets.py endpoints.jsonl --work-units wu.json`.

## 4. Duplicate-and-mutate parameter fuzzer

Replays a copy of each matching flow with a payload in each parameter — the
original traffic is untouched, mutated copies are tagged so a response hook can
grade them.

```python
"""param_fuzz.py — for each in-scope request, replay one mutated copy per param.
Run: mitmdump -s param_fuzz.py --set fuzz_filter='~d example\\.com & ~u /api/'
"""
from mitmproxy import ctx, http, flowfilter

PAYLOADS = ["'\"<svg/onload=alert(1)>", "' OR '1'='1", "../../../../etc/passwd", "${{7*7}}"]

class ParamFuzz:
    def load(self, loader):
        loader.add_option("fuzz_filter", str, "~u /api/", "filter for flows to fuzz")

    def configure(self, updates):
        self.matcher = flowfilter.parse(ctx.options.fuzz_filter)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.is_replay or flow.metadata.get("fuzzed") or not self.matcher(flow):
            return
        for where, params in (("query", flow.request.query),
                              ("form", flow.request.urlencoded_form)):
            for name in list(params.keys()):
                for payload in PAYLOADS:
                    f2 = flow.copy()
                    f2.metadata["fuzzed"] = f"{where}:{name}"
                    f2.metadata["payload"] = payload
                    tgt = f2.request.query if where == "query" else f2.request.urlencoded_form
                    tgt[name] = payload
                    ctx.master.commands.call("replay.client", [f2])

    def response(self, flow: http.HTTPFlow) -> None:
        tag, payload = flow.metadata.get("fuzzed"), flow.metadata.get("payload", "")
        if not tag or not flow.response:
            return
        body = flow.response.get_text(strict=False) or ""
        if payload and payload in body:
            ctx.log.warn(f"REFLECTED {tag} {payload!r} -> {flow.request.pretty_url}")
            flow.marked = ":boom:"
        if flow.response.status_code >= 500 or "SQL syntax" in body:
            ctx.log.warn(f"ERROR {flow.response.status_code} {tag} -> {flow.request.pretty_url}")
            flow.marked = ":bomb:"

addons = [ParamFuzz()]
```

Reflections found here are *leads*: hand the URL+param to dalfox
(`dalfox scan "https://example.com/api/search?q=1" -p q -o out.jsonl -f jsonl`) or
sqlmap for confirmation, then report via `findings.report`.

## 5. Tag flows matching a filter

```python
"""tagger.py — mark/comment flows for later triage; works offline too.
Run: mitmdump -nr capture.mitm -s tagger.py -w tagged.mitm
"""
from mitmproxy import http, flowfilter

RULES = {
    ":key:":     flowfilter.parse('~hq "Authorization" | ~hq "Cookie"'),
    ":bomb:":    flowfilter.parse("~c 500 | ~bs 'stack trace'"),
    ":mag:":     flowfilter.parse("~u /(admin|debug|internal|actuator)/"),
    ":satellite:": flowfilter.parse("~websocket"),
}

def response(flow: http.HTTPFlow) -> None:
    for mark, matcher in RULES.items():
        if matcher(flow):
            flow.marked = mark
            flow.comment = (flow.comment + " " if flow.comment else "") + mark
```

Then view only tagged flows: `mitmproxy -r tagged.mitm --set view_filter='~marked'`.

## 6. WebSocket tampering

```python
from mitmproxy import http

def websocket_message(flow: http.HTTPFlow):
    msg = flow.websocket.messages[-1]
    if msg.from_client and b'"amount"' in msg.content:
        msg.content = msg.content.replace(b'"amount":100', b'"amount":1')
```

## Options & logging conventions

- Define options in `load()`, read in `configure()`/hooks via `ctx.options.x`,
  set from the CLI with `--set x=value`. This is how shipped addons stay reusable.
- `ctx.log` output goes to the event log (TUI `E` / mitmdump stderr); use
  `.warn`/`.error` for hits so they stand out at `-q`.
- Avoid blocking I/O in hooks on busy proxies; line-buffered appends (as in the
  harvester) are fine.
- `flow.is_replay` is `"request"` on client-replayed flows — guard against
  fuzz-replay loops with it.
