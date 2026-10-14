# sslscan + openssl s_client reference

## sslscan (2.x)

Fast C scanner: enumerates protocols and accepted ciphers, grabs the cert,
checks Heartbleed/renegotiation/compression/fallback. Statically linked
builds support SSLv2/SSLv3 probing even where the system OpenSSL refuses.

### Flags

| Flag | Effect |
|---|---|
| `sslscan example.com:443` | default scan (port 443 if omitted) |
| `--targets=targets.txt` | one `host[:port]` per line |
| `--xml=out.xml` / `--xml=-` | machine-readable XML (to file / stdout) |
| `--no-colour` | plain text (clean evidence capture / piping) |
| `--show-certificate` | full certificate dump (subject, issuer, SANs, key) |
| `--show-certificates` | the whole presented chain |
| `--show-client-cas` | client-CA list the server requests |
| `--no-cipher-details` | skip EC/DHE strength annotation |
| `--no-failed` | legacy: only show accepted ciphers (default in 2.x) |
| `--ssl2 --ssl3 --tls10 --tls11 --tls12 --tls13` | restrict to one version |
| `--tlsall` | force-test all TLS versions |
| `--bugs` | enable SSL_OP_ALL workarounds for broken stacks |
| `--starttls-smtp` `--starttls-imap` `--starttls-pop3` `--starttls-ftp` `--starttls-ldap` `--starttls-mysql` `--starttls-psql` `--starttls-xmpp` `--starttls-irc` | STARTTLS modes (`--xmpp-server`/`--xmpp-client` variants for xmpp) |
| `--sni-name=example.com` | SNI different from the connect host (IP scanning / vhosts) |
| `--ipv4` / `--ipv6` | address family |
| `--timeout=<s>`, `--sleep=<ms>` | pacing |
| `--ocsp` | OCSP stapling status |
| `--rdp` | pre-TLS RDP negotiation |

### Reading the text output

```
SSL/TLS Protocols:
SSLv2     disabled   SSLv3     enabled    TLSv1.0   enabled
TLSv1.1   enabled    TLSv1.2   enabled    TLSv1.3   disabled

TLS Fallback SCSV:   Server does not support TLS Fallback SCSV
TLS renegotiation:   Secure session renegotiation supported
TLS Compression:     Compression disabled
Heartbleed:          TLSv1.2 not vulnerable to heartbleed

Supported Server Cipher(s):
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  112 bits  DES-CBC3-SHA
Accepted  TLSv1.0  128 bits  AES128-SHA
```

Color code (when colour on): **red** = broken (SSLv2/SSLv3 enabled, NULL/anon/
EXPORT/RC4/DES, <56-bit, SHA-1 cert sig, expired cert), **yellow** = weak
(3DES, 112-bit, CBC on TLS1.0/1.1, 1024-bit DHE), **purple** on `ADH`/`AECDH`
= anonymous key exchange. The `DHE <bits>` / `Curve` suffix is your Logjam /
weak-group evidence. Cert block shows subject, altnames, issuer, validity
dates, self-signed status.

### XML schema (2.0+)

```xml
<document title="SSLScan Results" version="2.1.x">
 <ssltest host="example.com" sniname="example.com" port="443">
  <protocol type="ssl" version="3" enabled="1"/>
  <protocol type="tls" version="1.0" enabled="1"/>
  <protocol type="tls" version="1.3" enabled="0"/>
  <fallback supported="0"/>
  <renegotiation supported="1" secure="1"/>
  <compression supported="0"/>
  <heartbleed sslversion="TLSv1.2" vulnerable="0"/>
  <cipher status="accepted" sslversion="TLSv1.2" bits="112"
          cipher="DES-CBC3-SHA" id="0x000A" strength="medium"
          dhebits="1024"/>
  <group sslversion="TLSv1.3" bits="128" name="secp256r1" id="0x0017"/>
  <certificates>
   <certificate type="short">
    <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
    <pk error="false" type="RSA" bits="2048"/>
    <subject>example.com</subject>
    <altnames>DNS:example.com, DNS:www.example.com</altnames>
    <issuer>R11</issuer>
    <self-signed>false</self-signed>
    <not-valid-before>Jan  1 00:00:00 2025 GMT</not-valid-before>
    <not-valid-after>Apr  1 00:00:00 2025 GMT</not-valid-after>
    <expired>true</expired>
   </certificate>
  </certificates>
 </ssltest>
</document>
```

Note the 2.0 schema change: certificates are wrapped in `<certificates>` with a
`type` attribute (`short`/`full`); pre-2.0 had a bare `<certificate>`.
`scripts/parse_testssl.py --sslscan out.xml` handles both and derives findings
from: enabled SSLv2/SSLv3/TLS1.0/TLS1.1, weak/anon/export/RC4/3DES/low-bit
ciphers, `dhebits<=1024`, heartbleed `vulnerable="1"`, insecure renegotiation,
compression enabled, missing fallback SCSV (when legacy protocols are on),
expired/self-signed certs and keys <2048 bits.

## openssl s_client — manual confirmation recipes

Always pass `-servername` (SNI) when the target has vhosts; without it you may
test the default cert/config, not the one in scope. Close stdin with
`</dev/null` (or `echo |`) so the session terminates.

### Negotiation basics

```sh
openssl s_client -connect example.com:443 -servername example.com </dev/null
```

Read in the output:
- `Certificate chain` — depth-numbered `s:`/`i:` subject/issuer lines; a chain
  of one self-issued cert = self-signed; missing intermediates show as
  `unable to get local issuer certificate` in `Verify return code`.
- `Protocol  :` and `Cipher    :` in the SSL-Session block — the negotiated pair.
- `Server Temp Key:` (e.g. `X25519, 253 bits` or `DH, 1024 bits`) — key-exchange
  strength; `DH, 1024 bits` corroborates Logjam-grade DHE.
- `Verify return code: 0 (ok)` vs `10 (certificate has expired)`,
  `18 (self-signed certificate)`, `21 (unable to verify the first certificate)`.

### Force a protocol version

```sh
openssl s_client -connect example.com:443 -servername example.com -ssl3    </dev/null  # usually needs legacy build
openssl s_client -connect example.com:443 -servername example.com -tls1    </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_1  </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_2  </dev/null
openssl s_client -connect example.com:443 -servername example.com -tls1_3  </dev/null
# ranges: -min_protocol TLSv1 -max_protocol TLSv1
```

Success ⇒ `Protocol : TLSv1` in SSL-Session = the server really negotiates it.
Failure modes to distinguish: `sslv3 alert handshake_failure` (server refused —
good config) vs `no protocols available` / `unsupported protocol` (**your**
openssl refused — modern builds disable SSLv3/TLS1.0 at compile time or via
`SECLEVEL`). Lower the local policy to make the client willing:

```sh
openssl s_client -connect example.com:443 -servername example.com \
  -tls1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null
```

If your build simply lacks SSLv3, trust testssl.sh (bundled legacy binaries)
or sslscan's static build for the SSLv2/SSLv3 verdict.

### Force a cipher

```sh
# TLS <= 1.2
openssl s_client -connect example.com:443 -servername example.com \
  -tls1_2 -cipher 'DES-CBC3-SHA' </dev/null                      # Sweet32 evidence
openssl s_client -connect example.com:443 -servername example.com \
  -cipher 'RC4' </dev/null
openssl s_client -connect example.com:443 -servername example.com \
  -cipher 'EXPORT:eNULL:aNULL@SECLEVEL=0' </dev/null             # FREAK / NULL / anon
# TLS 1.3 suites use a separate option
openssl s_client -connect example.com:443 -servername example.com \
  -ciphersuites 'TLS_AES_128_CCM_8_SHA256' </dev/null
# list what your client can offer
openssl ciphers -v 'ALL:@SECLEVEL=0'
```

### Certificate checks

```sh
# dates / subject / issuer / SANs of the leaf
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer -ext subjectAltName
# full decode
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -text
# save the whole chain for the report
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null \
  2>/dev/null > chain.pem
# key size + signature algorithm
openssl x509 -in chain.pem -noout -text | grep -E 'Public-Key|Signature Algorithm'
# OCSP stapling
openssl s_client -connect example.com:443 -servername example.com -status </dev/null \
  2>/dev/null | sed -n '/OCSP response/,/Next Update/p'
```

### Renegotiation / compression / STARTTLS

```sh
# secure renegotiation support is printed in every handshake:
#   "Secure Renegotiation IS supported" / "IS NOT supported"
# client-initiated renegotiation: type R + Enter in an interactive s_client session;
#   a renegotiating server re-handshakes, a safe one sends no_renegotiation/closes.
openssl s_client -connect example.com:443 -servername example.com
# compression: "Compression: NONE" vs a method name (CRIME if present)
openssl s_client -connect example.com:443 -comp </dev/null | grep -i compression
# STARTTLS
openssl s_client -connect 198.51.100.25:587 -starttls smtp </dev/null
openssl s_client -connect 198.51.100.25:143 -starttls imap </dev/null
# -starttls also: pop3, ftp, ldap, xmpp, xmpp-server, irc, mysql, postgres, lmtp, nntp, sieve
```
