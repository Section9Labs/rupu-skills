# testssl.sh reference

testssl.sh is a bash script (bundled OpenSSL binaries for legacy protocol
support) that performs the complete TLS audit. Current stable: 3.x. Run
`testssl.sh --help` to confirm local flags.

## Invocation forms

```sh
testssl.sh example.com                      # port 443 implied
testssl.sh https://example.com:8443         # URL form
testssl.sh 192.0.2.10:443                   # host:port
testssl.sh -t smtp 198.51.100.25:587        # STARTTLS protocol
testssl.sh --file targets.txt               # mass scan; one target (any form above) per line
testssl.sh --parallel --file targets.txt    # concurrent mass scan
```

If a hostname resolves to multiple IPs, testssl.sh scans each; pin one with
`--ip <addr>` (SNI stays the hostname) or `--ip one`.

## Output files

| Flag | Effect |
|---|---|
| `--jsonfile out.json` (`-oj`) | **flat** JSON: one array of finding objects |
| `--json-pretty` / `-oJ out.json` | **structured** JSON: metadata + `scanResult` grouped per target/section |
| `--csvfile out.csv` (`-oC`) | CSV, same fields as flat JSON |
| `--htmlfile out.html` (`-oH`) | HTML report |
| `-oA <base>` / `--outFile <base>` | all formats at once as `<base>.json/.csv/.html/.log` |
| `--logfile out.log` (`-oL`) | terminal transcript |
| `--severity LOW|MEDIUM|HIGH|CRITICAL` | filter what goes into the **file** outputs (terminal unaffected) |
| `--append` | append instead of refusing to overwrite |

Flat JSON finding object:

```json
{
  "id"       : "SSLv3",
  "ip"       : "example.com/203.0.113.5",
  "port"     : "443",
  "severity" : "HIGH",
  "cve"      : "CVE-2014-3566",
  "cwe"      : "CWE-757",
  "finding"  : "offered"
}
```

`ip` is `host/ip-address` — split on `/` for the hostname. `cve` may hold
several space-separated CVEs. Pretty JSON wraps the same objects in sections:

```json
{
  "Invocation": "...", "version": "3.2", "startTime": "...",
  "scanResult": [
    {
      "targetHost": "example.com", "ip": "203.0.113.5", "port": "443",
      "protocols":        [ {"id": "SSLv3", "severity": "HIGH", "finding": "offered", ...} ],
      "ciphers":          [ ... ],
      "serverPreferences":[ ... ],
      "fs":               [ ... ],
      "serverDefaults":   [ ... ],
      "headerResponse":   [ ... ],
      "vulnerabilities":  [ ... ],
      "cipherTests":      [ ... ],
      "browserSimulations": [ ... ]
    }
  ]
}
```

`scripts/parse_testssl.py` accepts both forms transparently.

## Severity map (testssl → rupu)

| testssl | rupu `findings.report` severity |
|---|---|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFO`, `OK` | `info` (dropped by default `--min-severity LOW`) |
| `WARN`, `DEBUG`, `FATAL` | scan-engine noise, never report (parser drops) |

## Section flags (run subsets)

| Flag | Section |
|---|---|
| `-p` / `--protocols` | SSLv2…TLS1.3 + SPDY/HTTP2 ALPN |
| `-s` / `--std` | standard cipher categories (NULL/EXPORT/LOW/3DES/…) |
| `-E` / `--cipher-per-proto` | every accepted cipher, per protocol version |
| `-P` / `--server-preference` | cipher order preference (server vs client) |
| `-S` / `--server-defaults` | certificate(s), key size/sig alg, chain, validity, OCSP stapling, session params |
| `-f` / `--fs` | forward-secrecy ciphers and groups |
| `-h` / `--header` | HTTP security headers (HSTS, cookies, etc.) |
| `-U` / `--vulnerable` | **all** vulnerability tests |
| `-e` / `--each-cipher` | every cipher testssl knows, brute enumeration |
| `-x <pat>` / `--single-cipher` | ciphers matching pattern |

## Individual vulnerability flags

| Flag | Tests | JSON `id` |
|---|---|---|
| `-H` / `--heartbleed` | Heartbleed (CVE-2014-0160) | `heartbleed` |
| `-I` / `--ccs` | CCS injection (CVE-2014-0224) | `CCS` |
| `-T` / `--ticketbleed` | Ticketbleed (CVE-2016-9244) | `ticketbleed` |
| `--robot` | ROBOT Bleichenbacher oracle | `ROBOT` |
| `-R` / `--renegotiation` | secure renegotiation / client-initiated reneg | `secure_renego`, `secure_client_renego` |
| `-C` / `--compression` / `--crime` | TLS compression (CRIME) | `CRIME_TLS` |
| `-B` / `--breach` | HTTP compression on secrets (BREACH) | `BREACH` |
| `-O` / `--poodle` | POODLE SSLv3 (CVE-2014-3566) | `POODLE_SSL` |
| `-Z` / `--tls-fallback` | TLS_FALLBACK_SCSV support | `fallback_SCSV` |
| `-W` / `--sweet32` | 64-bit-block ciphers (CVE-2016-2183) | `SWEET32` |
| `-F` / `--freak` | EXPORT-RSA ciphers (CVE-2015-0204) | `FREAK` |
| `-D` / `--drown` | SSLv2 (CVE-2016-0800) | `DROWN` |
| `-J` / `--logjam` | DH export / common primes (CVE-2015-4000) | `LOGJAM`, `LOGJAM-common_primes` |
| `-A` / `--beast` | CBC on SSL3/TLS1.0 (CVE-2011-3389) | `BEAST`, `BEAST_CBC_TLS1` |
| `-L` / `--lucky13` | Lucky13 CBC padding timing | `LUCKY13` |
| `-WS` / `--winshock` | Winshock (CVE-2014-6321) | `winshock` |
| `-4` / `--rc4` | RC4 ciphers | `RC4` |

Common high-value JSON ids outside the vuln section: `SSLv2`, `SSLv3`,
`TLS1`, `TLS1_1`, `TLS1_2`, `TLS1_3` (finding `offered` / `not offered`),
`cert_expirationStatus`, `cert_notAfter`, `cert_trust`, `cert_chain_of_trust`,
`cert_signatureAlgorithm`, `cert_keySize`, `cert_commonName`, `cert_san`,
`OCSP_stapling`, `HSTS`, `cipherlist_3DES_IDEA`, `cipherlist_EXPORT`,
`cipherlist_NULL`, `cipherlist_aNULL`, `cipherlist_LOW`, `cipher_order`,
`DH_groups`.

## Connection / behavior tuning

| Flag | Effect |
|---|---|
| `-t <proto>` / `--starttls <proto>` | smtp, pop3, imap, ftp, xmpp, telnet, ldap, irc, lmtp, nntp, postgres, mysql, sieve |
| `--xmpphost <domain>` | XMPP to-domain for STARTTLS xmpp |
| `-n` / `--nodns none|min` | skip DNS lookups |
| `--sneaky` | less obvious user agent / referer in HTTP checks |
| `--fast` | server-preference-only cipher runs (faster, less complete) |
| `--ssl-native` | use host openssl only (fewer legacy checks — avoid unless forced) |
| `--openssl <path>` | alternate openssl binary |
| `--mapping rfc|no-rfc|openssl` | cipher naming in output |
| `--proxy host:port` / `--proxy auto` | scan through a proxy |
| `--mtls <cert+key.pem>` / `--pwd` | client certificate authentication |
| `--basicauth user:pass` | HTTP auth for header checks |
| `--add-ca <pem>` | add internal root CA(s) to the trust check |
| `--connect-timeout <s>` / `--openssl-timeout <s>` | timeouts for dead/slow hosts |
| `--ids-friendly` | skip tests likely to trip IDS signatures (Heartbleed/CCS/Ticketbleed/ROBOT) — only when stealth outranks completeness |
| `--phone-out` | allow CRL/OCSP/intermediate-CA fetches from the internet (more complete cert verdicts) |
| `--parallel` + `--file` | mass scanning; `--mode serial` to force sequential |
| `--warnings off|batch` | non-interactive runs (cron/CI) |
| `--quiet`, `--color 0` | clean logs |

## Reading the terminal output

Order: SNI/DNS banner → protocols → cipher categories → FS → server
preferences → server defaults (cert block: serial, key size, signature
algorithm, CN/SAN vs hostname, chain of trust against bundled CA stores,
validity window, OCSP must-staple/stapling, CT) → HTTP headers → the
vulnerability block → cipher-per-protocol list → client simulations (what
Android/Java/OpenSSL versions would negotiate). Every non-OK line carries the
same severity word that lands in the JSON. The client-simulation block is
useful impact evidence: it shows real clients that would actually negotiate a
weak protocol/cipher.
