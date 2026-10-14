# mitmproxy — front-ends, modes, CA setup, filters, capture & replay

## Front-ends

All three binaries share flags, options (`--set`), addons (`-s`), and flow-file
format. Default proxy listen address: `*:8080`.

- `mitmproxy` — interactive terminal UI. Needs a real TTY.
- `mitmdump` — headless. Prints flows to stdout (`--set flow_detail=0..4` controls
  verbosity; `0` silent, `1` one-line, `3` headers+truncated body, `4` full body,
  useful for grabbing raw requests). `-q` quiet, `-v` verbose event log.
- `mitmweb` — web UI, default `http://127.0.0.1:8081` (`--web-port`, `--web-host`;
  it prints a tokenized URL on start). Can export flows as HAR from the UI.

Common flags:

```
--listen-host 0.0.0.0        bind address (default all on recent versions; pin it)
--listen-port 8080           proxy port
-p 8080                      same as --listen-port
--mode <spec>                proxy mode, repeatable
-s addon.py                  load addon (repeatable, hot-reloaded)
--set key=value              set any option (repeatable)
-w file / -w +file           stream flows to file / append
-r file                      read flows from file
-n                           do not bind a proxy port (offline)
-C file                      client-replay flows from file
-S file                      server-replay: answer requests from recorded responses
-k / --ssl-insecure          do not verify upstream server certificates
--ignore-hosts <regex>       TCP-passthrough matching host:port (no TLS interception)
--allow-hosts <regex>        inverse: only intercept matching hosts
--map-remote  "|regex|replacement"   rewrite URLs to a different server
--map-local   "|url-regex|/local/dir"  serve local files for matching URLs
--modify-headers "/filter/name/value"  declarative header rewrite (no script needed)
--modify-body    "/filter/regex/replacement"
--anticache / --anticomp     strip caching / accept-encoding headers
--showhost                   display Host header instead of resolved address
--certs example.com=/path/cert.pem   use a specific leaf cert (reverse mode)
```

A trailing **positional argument is a filter expression** applied as capture/display
filter: `mitmdump -w out.mitm "~d example\.com & !~u \.png$"`.

## CA / TLS setup

- CA material is generated on first run in `~/.mitmproxy/`:
  `mitmproxy-ca.pem` (key+cert — protect it), `mitmproxy-ca-cert.pem`,
  `mitmproxy-ca-cert.cer` (Android naming), `mitmproxy-ca-cert.p12` (Windows).
- Easiest install path: configure the client to use the proxy, visit
  `http://mitm.it`, pick the platform. If mitm.it says "traffic is not passing
  through mitmproxy", the proxy settings are wrong — fix that first.
- Linux system store: `cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt && update-ca-certificates`.
- Java clients: `keytool -importcert -alias mitm -cacerts -file ~/.mitmproxy/mitmproxy-ca-cert.pem`.
- Python requests: `REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem`;
  Node: `NODE_EXTRA_CA_CERTS=...`.
- Android >= 7: user-store CAs are ignored by default. Options: system store on a
  rooted device (`/system/etc/security/cacerts/<hash>.0`, hash via
  `openssl x509 -subject_hash_old`), re-sign the APK with a permissive
  `networkSecurityConfig`, or Frida/objection to disable pinning at runtime.
- iOS: install the profile, then Settings → General → About → Certificate Trust
  Settings → enable full trust.
- Pinned apps: TLS handshake failures appear in the event log; pass those hosts
  through with `--ignore-hosts` or defeat pinning with instrumentation.
- `--ssl-insecure` only affects the **upstream** leg (mitmproxy → server). Needed
  for self-signed staging servers; it never affects client trust.

## Modes in detail (`--mode`)

### regular (default)
Explicit HTTP(S) proxy. Client config: browser proxy settings, `http_proxy`/
`https_proxy` env vars, `curl -x http://192.0.2.10:8080`, Java
`-Dhttps.proxyHost=192.0.2.10 -Dhttps.proxyPort=8080`. Also speaks HTTP/1 CONNECT,
HTTP/2, and acts as an HTTP(S)-aware forwarder.

### transparent
Client is unaware; you must route its packets to the proxy box and redirect:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmproxy --mode transparent --showhost
```

Use for devices/apps that ignore proxy settings when you control the gateway
(rogue AP, lab router, emulator host).

### reverse:URL[@port]
`--mode reverse:https://example.com@443` — mitmproxy listens as if it were the
server and forwards to the given origin. Point the client at mitmproxy via DNS or
hosts-file (`203.0.113.7 api.example.com`). Perfect for thick clients with a fixed
API hostname and for capturing a single service. Multiple reverse modes with
different `@listen-ports` can front several origins at once. Also works for raw
TCP/TLS (`reverse:tls://...`) and DNS/UDP targets.

### upstream:URL
`--mode upstream:http://198.51.100.5:8081` — forward everything through another
proxy (Burp, egress proxy) while keeping mitmproxy's scripting/recording.
`--upstream-auth user:pass` if the next hop requires auth.

### socks5
`--mode socks5` for SOCKS-only clients (`curl --socks5-hostname 192.0.2.10:8080`).

### local
`--mode local` intercepts all local traffic via OS redirection (WinDivert/pf/
eBPF-level machinery); `--mode local:curl,example-client` restricts to process
names or PIDs. The best option for thick clients running on the proxy host — no
network reconfiguration, no proxy awareness required.

### wireguard
`--mode wireguard` starts a WireGuard server on UDP 51820 and prints/writes a
client config (also shown as QR in mitmweb). Install it in the stock WireGuard
app on the phone → all device traffic transits mitmproxy. No root, no AP tricks.
`--mode wireguard:path/to/keyfile` persists keys. CA install is still required
for TLS interception.

Modes are repeatable and run concurrently: `--mode regular --mode wireguard`.

## Filter language

Used for: view filter (`f` / `--set view_filter=`), intercept (`i` /
`--intercept`), capture subset (trailing positional), replay subsetting,
`--modify-headers`/`--modify-body` prefixes, and `flow.match()` in addons.

| Expr | Matches |
|---|---|
| `~u <re>` | URL |
| `~d <re>` | domain (host) |
| `~m <re>` | method (`~m POST`) |
| `~q` | request has no response yet (i.e., it's a request) |
| `~s` | response exists |
| `~c <int>` | response status code (`~c 500`) |
| `~h <re>` | any header (request or response) |
| `~hq <re>` / `~hs <re>` | request / response header |
| `~b <re>` | any body |
| `~bq <re>` / `~bs <re>` | request / response body |
| `~t <re>` | content-type |
| `~a` | asset types (css/js/images/fonts) — `!~a` hides noise |
| `~e` | flow has an error |
| `~marked` / `~marker <re>` | marked flows |
| `~comment <re>` | flow comment |
| `~websocket` / `~http` / `~tcp` / `~dns` | protocol class |
| `~src <re>` / `~dst <re>` | client / server address |
| `~all` | everything |

Combinators: `&` and, `|` or, `!` not, `( )` grouping. Bare strings are
"URL or body contains". Regexes are Python-flavored, case-insensitive by default.

Examples:

```
~d example\.com & ~m POST & !~a
~u /api/v[0-9]+/ & ~s & ~c 200
~hq "Authorization" & ~d api\.example\.com
~bs "stack trace" | ~c 500
```

## Capture, replay, offline

```sh
# Capture — stream to disk while proxying (crash-safe, written continuously)
mitmdump -w capture.mitm
mitmdump -w +capture.mitm            # append to existing file
mitmdump -w cap.mitm "~d example\.com & !~a"   # filtered at capture time

# Offline read/transform:  -n (no proxy bind) + -r (read file)
mitmdump -nr capture.mitm --set flow_detail=1              # list flows
mitmdump -nr capture.mitm --set flow_detail=4 "~u /login"  # dump full raw req/resp
mitmdump -nr capture.mitm -w api.mitm "~d api\.example\.com & ~m POST"
mitmdump -nr capture.mitm -s harvest_addon.py              # addon over a capture

# Client replay — re-send recorded requests to the live server, one at a time
mitmdump -nC api.mitm                       # replay offline
mitmdump -C api.mitm -w replayed.mitm       # replay AND keep proxying/recording
# Combine with --modify-headers to replay as another user:
mitmdump -nC api.mitm --modify-headers "/~q/Cookie/session=OTHERUSER" -w asuser2.mitm

# Server replay — answer clients from recorded responses (offline app testing,
# or feeding a scanner canned responses)
mitmdump -S api.mitm --set server_replay_extra=kill
```

Flow files are a binary stream of serialized flows; treat them as the source of
truth for evidence (exact request/response bytes). Export individual flows as raw
HTTP / curl / httpie from the TUI (`E`) or mitmweb; export HAR from mitmweb or
`mitmdump -nr capture.mitm --set hardump=./capture.har` (recent versions bundle a
HAR export addon).

## Useful options (`--set`)

```
flow_detail=0..4          mitmdump print verbosity
view_filter=<filter>      limit what the TUI shows
intercept=<filter>        intercept matching flows (same as TUI `i`)
save_stream_file=+f.mitm  stream capture (same as -w)
stream_large_bodies=1m    pass huge bodies through without buffering (addons
                          won't see streamed bodies — disable while tampering)
connection_strategy=lazy  don't connect upstream until needed (server replay)
http2=false               force HTTP/1.1 if an addon chokes on h2 specifics
websocket=true            WS interception (default on)
ssl_insecure=true         same as -k
block_global=false        allow non-local clients to connect (needed for devices)
anticache=true            strip If-None-Match/If-Modified-Since (see real bodies)
console_eventlog_verbosity=debug   TLS failure diagnosis in the TUI event log
```

`mitmdump --options` dumps every option with defaults; `mitmproxy` TUI: `O` opens
the options editor.
