---
name: tls-testing
description: Assess the TLS/SSL configuration of any HTTPS or STARTTLS service — protocol versions, cipher suites, certificate chain/validity, key-exchange strength, and named vulnerabilities (Heartbleed, ROBOT, DROWN, CCS injection, Ticketbleed, POODLE, BEAST, Sweet32, Logjam, FREAK, insecure renegotiation, CRIME) — using testssl.sh as the authoritative scanner, sslscan as a fast second opinion, and openssl s_client for manual confirmation. Use on every HTTPS endpoint in the inventory (WSTG-CRYP-01).
license: Apache-2.0
metadata:
  author: Section9Labs
---

# TLS/SSL Configuration Testing

Audit the transport layer of every TLS endpoint: which protocol versions the
server negotiates, which cipher suites it accepts and prefers, whether the
certificate chain is valid, and whether the implementation is vulnerable to any
of the named TLS attacks. Workflow: **testssl.sh (JSON) → sslscan (cipher
table) → openssl s_client (manual confirmation) → parse → rupu findings**.

Every parse/handoff step below ends in rupu-ingestible output (work-units JSON
array, `assets.mark`, or `findings.report`). Exact JSON shapes:
`references/rupu.md`.

## Inputs

- A host:port list of TLS services (from the port-scan / httpx inventory —
  anything on 443/8443/etc., plus STARTTLS-capable mail/ldap/ftp ports:
  25, 110, 143, 389, 587, 990, etc.).
- Mark each target as an asset first: `assets.mark` kind `web:site`,
  coordinates `[{"t":"url","v":"https://192.0.2.10:443"}]`, depth `mapped`.

## Step 1 — testssl.sh: the authoritative audit

testssl.sh tests everything (protocols, ciphers, server preference, forward
secrecy, cert, HTTP security headers, all named vulns) and tags every finding
with a severity (`INFO|OK|LOW|MEDIUM|HIGH|CRITICAL`) plus CVE/CWE where known.

Full scan with machine-readable output (always write both JSON forms if disk
is cheap; the parser accepts either):

```sh
testssl.sh --jsonfile ts-example.json --htmlfile ts-example.html \
  https://example.com:443
# structured JSON (grouped per section, same fields per finding):
testssl.sh --json-pretty -oJ ts-example-pretty.json https://example.com:443
```

Faster, targeted runs when you only need part of the picture:

```sh
testssl.sh -p --jsonfile out.json example.com:443        # protocols only
testssl.sh -S example.com:443                            # server defaults / cert details
testssl.sh -P -E example.com:443                         # preference + ciphers per protocol
testssl.sh -U --jsonfile vulns.json example.com:443      # ALL vulnerability tests
testssl.sh -H example.com:443                            # Heartbleed only
testssl.sh --robot --ccs --drown --ticketbleed example.com:443
testssl.sh --poodle --sweet32 --logjam --freak --beast --crime example.com:443
```

STARTTLS, SNI tricks, and mass scanning:

```sh
testssl.sh -t smtp 198.51.100.25:587                     # STARTTLS (smtp|pop3|imap|ftp|xmpp|ldap|...)
testssl.sh --xmpphost example.net -t xmpp 203.0.113.5:5222
testssl.sh --sneaky --fast https://example.com           # low-profile, quicker cipher runs
testssl.sh --parallel --file targets.txt                 # mass: one line per host[:port], runs concurrently
testssl.sh --add-ca ./internal-root.pem https://example.com   # trust an internal CA
testssl.sh https://192.0.2.10:443 --ip 192.0.2.10        # pin IP, SNI stays the URL hostname
```

Read the terminal output top-down: protocol table (offered/not offered per
version), cipher categories, server preference order, certificate block
(issuer, validity, chain of trust, key size, OCSP stapling), then the
vulnerability section — each line severity-colored and the JSON mirrors it as
`{id, ip, port, severity, finding, cve, cwe}`. Everything `LOW` and above is a
candidate finding. Full flag reference, JSON formats, and the severity map:
`references/testssl.md`.

## Step 2 — sslscan: fast second opinion / cipher table

sslscan enumerates accepted ciphers per protocol in seconds. Use it to
cross-check testssl.sh's protocol/cipher claims and to get a compact table for
evidence.

```sh
sslscan --no-colour example.com:443                      # plain-text table for evidence
sslscan --show-certificate --xml=ss-example.xml example.com:443
sslscan --targets=targets.txt --xml=ss-all.xml           # mass scan from file
sslscan --starttls-smtp 198.51.100.25:25                 # also --starttls-imap|pop3|ftp|ldap|mysql|psql|xmpp
sslscan --bugs --tlsall example.com:443                  # workaround flags for broken stacks / force all TLS versions
```

Read the output: `SSLv2/SSLv3/TLSv1.0...TLSv1.3 enabled/disabled` header,
then one line per accepted cipher — version, bits, name, key-exchange detail
(e.g. `DHE 1024 bits` ⇒ Logjam-grade). Red = broken (SSLv2/v3, <56-bit,
RC4/NULL/EXPORT/anon), yellow = weak (3DES/Sweet32, 112-bit, CBC on old TLS).
It also reports TLS Fallback SCSV, renegotiation, compression, Heartbleed, and
the certificate. `--xml=` is the machine-readable form (2.0 schema wraps certs
in `<certificates>` with a `type` attribute); the parser in Step 4 ingests it.
Details: `references/sslscan-openssl.md`.

## Step 3 — openssl s_client: manual confirmation

Confirm every flagged protocol/cipher/cert issue by negotiating it yourself —
the transcript is your evidence.

```sh
# baseline handshake with SNI; read negotiated Protocol/Cipher + cert chain
openssl s_client -connect example.com:443 -servername example.com </dev/null

# confirm a weak protocol is actually negotiable
openssl s_client -connect example.com:443 -servername example.com -tls1   </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_1 </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_2 </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_3 </dev/null

# confirm a weak cipher (TLS<=1.2 uses -cipher; TLS1.3 uses -ciphersuites)
openssl s_client -connect example.com:443 -servername example.com \
  -cipher 'DES-CBC3-SHA' -tls1_2 </dev/null

# cert chain + expiry + OCSP stapling
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
openssl s_client -connect example.com:443 -servername example.com -status </dev/null \
  | grep -A5 'OCSP Response'
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer -ext subjectAltName

# STARTTLS by hand
openssl s_client -connect 198.51.100.25:587 -starttls smtp </dev/null
```

A successful weak negotiation prints `Protocol  : TLSv1` /
`Cipher    : DES-CBC3-SHA` in the session block — paste that into the finding
evidence. `handshake failure` / `no protocols available` means the server (or
your local openssl policy — check `openssl ciphers -v`) refused it; recheck
before reporting. Legacy-protocol caveats and more recipes:
`references/sslscan-openssl.md`.

## Step 4 — Parse, normalize, hand off to rupu

Run the bundled parser over the testssl.sh JSON (flat or pretty) and sslscan
XML. It filters to severity ≥ LOW (tunable), merges both tools, and emits all
three rupu shapes:

```sh
python3 scripts/parse_testssl.py ts-example.json ts-other.json \
  --sslscan ss-example.xml \
  --min-severity LOW \
  -o tls-merged.json \
  --work-units tls-units.json \
  --findings tls-findings.json
```

- `tls-merged.json` — normalized `{id, host, port, severity, finding, cve, cwe, source}`
  records, severity already mapped to rupu's `info|low|medium|high|critical`.
- `tls-units.json` — a clean JSON array (first char `[`) of work units, one per
  affected host:port, for a rupu workflow `for_each:` or lead-agent `dispatch`.
  Hand this array to the `work-units` skill to normalize/split further.
- `tls-findings.json` — ready `findings.report` payloads: scope `endpoint`,
  `target_ref` the `https://host:port/` URL, mapped severity,
  `evidence.rationale` built from the finding text + CVE, classification
  `WSTG-CRYP-01` plus the CWE when testssl provides one.

Then:

1. For each scanned host:port, bump the asset: `assets.mark` kind `web:site`,
   depth `tested` (or `exploited` if you demonstrated e.g. Heartbleed memory
   read). Record this via the `coverage-assets` skill.
2. For each payload in `tls-findings.json`, append your openssl confirmation
   transcript (Step 3) to `evidence` — the negotiated-handshake exchange is
   what satisfies the web profile's evidence check — and submit it via the
   `finding-report` skill (`findings.report`).
3. Dispatch `tls-units.json` for any follow-up (e.g. a Heartbleed hit fans out
   to an exploitation child; an expired/self-signed cert fans out to a
   MITM-impact assessment child).

Exact tool-call shapes and field rules: `references/rupu.md`.

## Triage guide (what matters)

| Observation | Verdict |
|---|---|
| SSLv2 offered | CRITICAL — DROWN surface, report immediately |
| SSLv3 offered | HIGH — POODLE |
| Heartbleed / ROBOT / CCS / Ticketbleed vulnerable | HIGH–CRITICAL — memory/key disclosure, confirm then exploit per authorization |
| TLS 1.0 / 1.1 offered | MEDIUM-LOW — deprecated (RFC 8996); BEAST-era CBC risk |
| 3DES / RC4 / EXPORT / NULL / anon ciphers accepted | HIGH (RC4/EXPORT/NULL) to MEDIUM (3DES = Sweet32) |
| DHE ≤ 1024-bit, or common primes | Logjam — HIGH if export-DHE, MEDIUM at 1024 |
| TLS compression on | CRIME — HIGH if cookies ride the channel |
| Client-initiated / insecure renegotiation | MEDIUM — DoS / plaintext injection |
| Cert expired / self-signed / hostname mismatch / <2048-bit RSA / SHA-1 sig | MEDIUM–HIGH depending on exposure |
| No TLS_FALLBACK_SCSV and old protocols enabled | adds downgrade weight to the protocol findings |

Per-vulnerability detail — what each bug is, which testssl `id` and output line
reveals it, and how to confirm it: `references/named-vulns.md`.

## References

- `references/testssl.md` — full testssl.sh flag set, JSON schemas, severity map.
- `references/sslscan-openssl.md` — sslscan flags/XML schema, openssl s_client confirmation recipes.
- `references/named-vulns.md` — Heartbleed, ROBOT, DROWN, CCS, Ticketbleed, POODLE, BEAST, Sweet32, Logjam, FREAK, renegotiation, CRIME: what they are and how they show in output.
- `references/rupu.md` — rupu wiring: work-unit, `assets.mark`, and `findings.report` shapes used by this skill.
