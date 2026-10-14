# Named TLS vulnerabilities — what they are and how they show in output

For each bug: the weakness, the CVE/CWE, how testssl.sh/sslscan report it, how
to confirm, and the severity to report (testssl's own tag is authoritative;
this table explains why).

## Heartbleed — CVE-2014-0160, CWE-119

OpenSSL 1.0.1–1.0.1f heartbeat extension missing bounds check: a malformed
heartbeat request leaks up to 64 KB of server process memory per probe —
private keys, session cookies, credentials.
- testssl: `-H`; JSON id `heartbleed`, `VULNERABLE` = CRITICAL. Output notes
  whether the heartbeat extension is even advertised ("not vulnerable, no
  heartbeat extension" = clean).
- sslscan: `<heartbleed sslversion="..." vulnerable="1"/>` per protocol.
- Confirm/exploit: repeated probes dump memory; `nmap --script ssl-heartbleed
  -p 443 192.0.2.10` or Metasploit `auxiliary/scanner/ssl/openssl_heartbleed`
  (set `ACTION DUMP`/`KEYS` to extract memory or the private key). A recovered
  secret upgrades the asset depth to `exploited`.

## ROBOT — Return Of Bleichenbacher's Oracle Threat (CVE-2017-13099 et al.), CWE-203

Padding-oracle on RSA PKCS#1 v1.5 key exchange: server responds differently to
malformed pre-master secrets, letting an attacker decrypt recorded RSA-key-
exchange sessions or sign with the server key. Only matters where static-RSA
cipher suites (`TLS_RSA_...`) are enabled.
- testssl: `--robot`; id `ROBOT`. "VULNERABLE (strong oracle)" = HIGH/CRITICAL;
  "weak oracle" = MEDIUM; "not vulnerable, no RSA key transport cipher" = clean.
- Confirm: the testssl check is itself the oracle probe; cross-check that
  `TLS_RSA` suites appear in the cipher list.

## DROWN — CVE-2016-0800, CWE-310

Cross-protocol attack: a server (or any other server sharing the same RSA
cert/key) that still speaks SSLv2 lets an attacker decrypt TLS sessions.
- testssl: `-D`; id `DROWN`. Reports SSLv2 service and warns if the cert is
  reused elsewhere (censys hint). SSLv2 offered anywhere = CRITICAL.
- sslscan: `<protocol type="ssl" version="2" enabled="1"/>`.
- Confirm: `testssl.sh -p` showing SSLv2 "offered"; modern openssl cannot
  speak SSLv2 — rely on testssl's bundled binary.
- Remember: check mail/ldap services sharing the web cert — they create DROWN
  exposure for the web endpoint.

## CCS injection — CVE-2014-0224, CWE-310

OpenSSL accepts a premature ChangeCipherSpec, forcing weak keying material; a
MITM between two vulnerable OpenSSL peers can decrypt/modify traffic.
- testssl: `-I`; id `CCS`. VULNERABLE = HIGH.
- Confirm: `nmap --script ssl-ccs-injection -p 443 192.0.2.10`.

## Ticketbleed — CVE-2016-9244, CWE-200

F5 BIG-IP session-ticket bug: server echoes 31 bytes of uninitialized memory
in the session ID when a short session ticket is sent. Leaks session data.
- testssl: `-T`; id `ticketbleed`. VULNERABLE = HIGH. Only runs/meaningful
  against F5-looking stacks.
- Confirm: repeat the testssl probe; leaked bytes differ per handshake.

## POODLE — CVE-2014-3566, CWE-310

SSLv3 CBC padding is unauthenticated; a MITM forcing downgrade to SSLv3 can
decrypt one byte per 256 requests (classic cookie theft). Variant: "POODLE
TLS" on broken middleboxes that reuse SSLv3 padding under TLS.
- testssl: `-O`; id `POODLE_SSL` — "VULNERABLE, uses SSLv3+CBC" = HIGH.
  Related: `fallback_SCSV` (`-Z`) — lack of TLS_FALLBACK_SCSV makes the
  downgrade practical, raising POODLE's weight.
- sslscan: SSLv3 enabled + CBC ciphers listed under SSLv3.
- Confirm: `openssl s_client -ssl3 -cipher 'AES128-SHA@SECLEVEL=0'` (legacy
  build) negotiates SSLv3+CBC.

## BEAST — CVE-2011-3389, CWE-20

Predictable IVs in SSLv3/TLS1.0 CBC: an in-browser attacker can decrypt
cookies block by block. Mitigated client-side (1/n-1 splitting) so modern
impact is LOW-MEDIUM, but it keeps TLS1.0+CBC reportable.
- testssl: `-A`; id `BEAST`/`BEAST_CBC_TLS1` — lists the CBC ciphers accepted
  on TLS1.0/SSLv3; severity LOW/MEDIUM ("VULNERABLE -- but also supports
  higher protocols" is the common, lower-impact case).
- Confirm: `openssl s_client -tls1 -cipher 'AES256-SHA@SECLEVEL=0'` succeeds.

## Sweet32 — CVE-2016-2183 / CVE-2016-6329, CWE-327

Birthday attacks on 64-bit-block ciphers (3DES, Blowfish, IDEA): after ~32 GB
of traffic on one connection, block collisions reveal plaintext (cookies).
- testssl: `-W`; id `SWEET32` — "VULNERABLE, uses 64 bit block ciphers" =
  MEDIUM(ish). The accepted suites appear as `DES-CBC3-SHA` /
  `cipherlist_3DES_IDEA`.
- sslscan: `bits="112"` 3DES lines.
- Confirm: `openssl s_client -tls1_2 -cipher 'DES-CBC3-SHA'` negotiates.

## Logjam — CVE-2015-4000, CWE-310

Downgrade to 512-bit export DHE, or use of weak/common 1024-bit DH primes that
nation-state-level precomputation can break.
- testssl: `-J`; ids `LOGJAM` (export DHE suites = HIGH) and
  `LOGJAM-common_primes` (named common prime / `DH_groups` shows the size).
- sslscan/openssl: `dhebits="1024"` attribute / `Server Temp Key: DH, 1024 bits`.
- Confirm: `openssl s_client -cipher 'EDH@SECLEVEL=0'` and read `Server Temp Key`.

## FREAK — CVE-2015-0204, CWE-310

Server accepts RSA_EXPORT (512-bit RSA) suites; MITM downgrades the handshake
and factors the ephemeral export key in hours.
- testssl: `-F`; id `FREAK` — "VULNERABLE, uses EXPORT RSA ciphers" = HIGH.
- Confirm: `openssl s_client -cipher 'EXPORT@SECLEVEL=0'` negotiates.

## Insecure / client-initiated renegotiation — CVE-2009-3555, CWE-310

Missing RFC 5746 secure-renegotiation extension lets a MITM splice a plaintext
prefix into the victim's session. Separately, allowing client-initiated
renegotiation enables cheap CPU-exhaustion DoS.
- testssl: `-R`; ids `secure_renego` (NOT supported = HIGH-ish MEDIUM) and
  `secure_client_renego` (supported = LOW/MEDIUM, DoS).
- sslscan: `<renegotiation supported="1" secure="0"/>` = insecure.
- Confirm: s_client prints `Secure Renegotiation IS/IS NOT supported`; type
  `R` in an interactive session to test client-initiated renegotiation.

## CRIME — CVE-2012-4929, CWE-310 (and BREACH — CVE-2013-3587)

TLS-level compression leaks secret lengths: attacker-controlled requests plus
compressed responses recover cookies byte-by-byte. BREACH is the HTTP-gzip
variant (needs reflected input + secret in response body).
- testssl: `-C` id `CRIME_TLS` ("VULNERABLE, uses compression" = HIGH when
  cookies are in play); `-B` id `BREACH` (potentially vulnerable = MEDIUM,
  needs app-level conditions).
- sslscan: `<compression supported="1"/>`.
- Confirm: `openssl s_client -comp` → `Compression: <method>` instead of NONE.

## RC4 — CVE-2013-2566 / CVE-2015-2808 (Bar-Mitzvah), CWE-327

RC4 keystream biases allow plaintext recovery with enough ciphertexts.
- testssl: `-4`; id `RC4` — any accepted RC4 suite = HIGH.
- Confirm: `openssl s_client -cipher 'RC4@SECLEVEL=0'`.

## Lucky13 — CVE-2013-0169, CWE-310

Timing side channel in CBC-mode MAC-then-encrypt. testssl `-L`, id `LUCKY13`;
reported LOW/MEDIUM when CBC suites remain — usually folded into the
"CBC ciphers offered" finding rather than reported alone.

## Deprecated protocols (no single CVE)

TLS 1.0/1.1 are prohibited by RFC 8996; SSLv3/SSLv2 by RFC 7568/6176. testssl
ids `SSLv2`/`SSLv3`/`TLS1`/`TLS1_1` with finding `offered`. Report even
without a named attack: compliance (PCI DSS 4.x) and downgrade surface.

## Certificate weaknesses (ids under serverDefaults)

| testssl id | Issue |
|---|---|
| `cert_expirationStatus` / `cert_notAfter` | expired or expiring cert |
| `cert_trust` / `cert_chain_of_trust` | untrusted/self-signed/incomplete chain |
| `cert_commonName` + `cert_san` | hostname mismatch |
| `cert_signatureAlgorithm` | SHA-1 / MD5 signature |
| `cert_keySize` | RSA < 2048 or weak EC |
| `OCSP_stapling` | no stapling (info, raises revocation-check weight) |

Each maps to CWE-295 (improper certificate validation surface) /
CWE-326 (inadequate key strength) and WSTG-CRYP-01.
