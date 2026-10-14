# rupu wiring for `tls-testing`

Every parse/handoff step in this skill ends in one of three rupu-ingestible
outputs: a **work-units JSON array**, **`assets.mark`** calls, or
**`findings.report`** calls. `scripts/parse_testssl.py` emits the first and
pre-builds the third; the agent issues the tool calls.

Shared skills to import by name (same rupu-skills library — do not re-invent):

- `work-units` — canonical work-unit splitter/normalizer. Hand it the array
  produced by `--work-units`.
- `coverage-assets` — recording assets / depth bumps around `assets.mark`.
- `finding-report` — writing a complete finding around `findings.report`.

## 1. Work units (fan-out)

`parse_testssl.py --work-units tls-units.json` writes a clean JSON array —
first character `[` — so a rupu workflow `for_each:` can JSON-parse the file
(read via the `read_file` tool), and a lead agent can read the same file and
`dispatch` one child per element. One unit per affected host:port:

```json
[
  {
    "id": "tls-example.com-443",
    "title": "TLS issues on example.com:443 (max severity: high)",
    "targets": ["https://example.com:443/"],
    "hints": {
      "host": "example.com",
      "port": "443",
      "max_severity": "high",
      "issue_ids": "SSLv3,POODLE_SSL,SWEET32,cert_expirationStatus",
      "issue_count": "4",
      "next": "confirm with openssl s_client, then findings.report"
    }
  }
]
```

Hand this array to the `work-units` skill for normalization/splitting before
dispatch. Typical fan-outs: a `heartbleed`/`ROBOT`/`CCS` hit → exploitation
child; cert-trust issues → MITM-impact child; deprecated protocols → policy
finding child.

## 2. Assets (`assets.mark`)

Record each TLS endpoint before scanning and bump its depth after. Kinds are
`web`-profile namespaced.

Before scanning (inventory intake):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://example.com:443"}],
  "label": "https://example.com:443",
  "depth": "mapped"
}
```

After the testssl/sslscan pass (the service was actively probed/vuln-tested):

```json
{
  "kind": "web:site",
  "coordinates": [{"t": "url", "v": "https://example.com:443"}],
  "label": "https://example.com:443",
  "depth": "tested"
}
```

If you demonstrated impact (e.g. dumped memory via Heartbleed, recovered a
secret via ROBOT), mark `"depth": "exploited"`. Depth ladder:
`mapped` → `crawled` → `tested` → `exploited` — always mark the rung actually
reached. Route the calls through the `coverage-assets` skill.

## 3. Findings (`findings.report`)

`parse_testssl.py --findings tls-findings.json` emits one payload per
normalized finding at or above `--min-severity`. TLS findings are pinned to
the service URL: scope `endpoint`, `target_ref` = `https://host:port/`
(use scope `host` only for genuinely host-wide issues such as a shared-key
DROWN exposure spanning multiple services). Severity is already mapped
(testssl CRITICAL/HIGH/MEDIUM/LOW/INFO → critical/high/medium/low/info).

The `web` profile's completeness checks require all three of: the finding
pinned to a route/url, an HTTP (here: TLS handshake) exchange in evidence, and
an OWASP-or-CWE classification. The script fills the first and third and
seeds the rationale; **the agent must append the Step-3 openssl transcript to
`evidence.exchange` before submitting** — the negotiated-handshake transcript
is the exchange evidence for a transport-layer finding.

Payload shape (as emitted; `evidence.exchange` placeholder to be replaced):

```json
{
  "title": "TLS: SSLv3 offered (POODLE) on example.com:443",
  "scope": "endpoint",
  "target_ref": "https://example.com:443/",
  "severity": "high",
  "classification": "OWASP WSTG-CRYP-01; CWE-757; CVE-2014-3566",
  "evidence": {
    "rationale": "testssl.sh id=SSLv3: offered. The server negotiates SSLv3, exposing CBC sessions to the POODLE padding-oracle attack (CVE-2014-3566). Corroborated by sslscan protocol table.",
    "exchange": "REPLACE: paste `openssl s_client -connect example.com:443 -servername example.com -ssl3` transcript showing `Protocol : SSLv3` in the SSL-Session block, plus the ClientHello/ServerHello summary."
  }
}
```

Classification rules used by the script:

- Always include `OWASP WSTG-CRYP-01` (Testing for Weak Transport Layer Security).
- Append the testssl `cwe` field when present (e.g. `CWE-310`, `CWE-757`),
  else fall back to `CWE-326` (inadequate encryption strength) for
  cipher/protocol findings and `CWE-295` for certificate-validation findings.
- Append the `cve` field when present.

Submit each payload with the `finding-report` skill (`findings.report` tool).
One finding per distinct weakness per host:port — do not merge POODLE with an
expired cert; do merge the 14 individual 3DES cipher lines into the one
Sweet32 finding (the script already collapses by testssl `id`).

## Step → output map

| Methodology step | rupu output |
|---|---|
| Inventory intake | `assets.mark` (`web:site`, depth `mapped`) |
| testssl.sh / sslscan runs parsed | merged JSON + `--work-units` array → `work-units` skill |
| Post-scan coverage | `assets.mark` depth `tested` (or `exploited`) via `coverage-assets` |
| openssl confirmation of each issue | `findings.report` payloads (evidence.exchange filled) via `finding-report` |
