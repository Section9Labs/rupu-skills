# rupu wiring for cms-testing

Every parse/handoff step in this skill ends in one of three rupu-ingestible
outputs: a **work-units JSON array**, **`assets.mark`** calls, or a
**`findings.report`** call. `scripts/parse_wpscan.py` emits all three shapes
from a wpscan JSON file. Shared skills referenced by name — do not re-invent:

- `work-units` — canonical splitter/normalizer; hand it any array this skill emits.
- `coverage-assets` — asset recording conventions behind `assets.mark`.
- `finding-report` — writing a complete finding behind `findings.report`.

## 1. Work units (fan-out)

A clean JSON **array** file whose first character is `[`. rupu's `for_each:`
JSON-parses it (read via the `read_file` tool); a lead agent reads the same
file and `dispatch`es one child per element.

```json
[
  {
    "id": "wp-plugin-contact-form-7-xss",
    "title": "Exploit: Contact Form 7 < 5.8 - Reflected XSS",
    "targets": ["https://192.0.2.10/"],
    "hints": {
      "cms": "wordpress",
      "component": "plugin:contact-form-7",
      "version": "5.7.1",
      "fixed_in": "5.8",
      "cves": "CVE-2023-XXXXX",
      "references": "https://wpscan.com/vulnerability/..."
    }
  },
  {
    "id": "wp-brute-admin-xmlrpc",
    "title": "Credential attack: admin via xmlrpc-multicall",
    "targets": ["https://192.0.2.10/xmlrpc.php"],
    "hints": {"cms": "wordpress", "usernames": "admin,editor",
              "attack": "xmlrpc-multicall"}
  }
]
```

Generate with: `python3 scripts/parse_wpscan.py wpscan.json --work-units wp-units.json`
then hand the normalized array to the `work-units` skill.

## 2. assets.mark

Web profile kinds are namespaced with `web:`. Depth ladder:
`mapped` -> `crawled` -> `tested` -> `exploited`. Mark the rung actually
reached: detected-only site = `mapped`; routes discovered by enumeration =
`crawled`; anything wpscan/joomscan/droopescan actively probed = `tested`;
confirmed RCE / valid admin creds = `exploited`.

Site:

```json
{"kind": "web:site", "label": "https://192.0.2.10 (WordPress 6.3.1)",
 "coordinates": [{"t": "url", "v": "https://192.0.2.10"}],
 "depth": "tested"}
```

Route (login surface, xmlrpc, admin panel):

```json
{"kind": "web:route", "label": "WordPress xmlrpc endpoint",
 "coordinates": [{"t": "url", "v": "https://192.0.2.10"},
                  {"t": "http_route", "v": "/xmlrpc.php"}],
 "depth": "tested"}
```

With a parameter (e.g. com_fields SQLi):

```json
{"kind": "web:route", "label": "Joomla com_fields list[fullordering] SQLi",
 "coordinates": [{"t": "url", "v": "https://192.0.2.20"},
                  {"t": "http_route", "v": "/index.php"},
                  {"t": "param", "v": "list[fullordering]"}],
 "depth": "exploited"}
```

`parse_wpscan.py --assets wp-assets.json` emits ready payloads; follow the
`coverage-assets` skill for the call itself.

## 3. findings.report

Scope `endpoint` with `target_ref` = affected URL (scope `host` only for
host-wide issues). The `web` profile completeness checks require all three of:
finding pinned to a route/url, an HTTP exchange in evidence, and an
OWASP (WSTG id or Top-10) or CWE classification.

```json
{
  "title": "WordPress core 6.3.1 - vulnerable plugin Contact Form 7 < 5.8 (XSS)",
  "scope": "endpoint",
  "target_ref": "https://192.0.2.10/wp-content/plugins/contact-form-7/",
  "severity": "medium",
  "classification": "CWE-79 / OWASP A03:2021 / WSTG-INPV-01",
  "evidence": {
    "rationale": "wpscan (mixed detection, version from readme.txt, confidence 80) identifies contact-form-7 5.7.1; WPScan DB maps CVE-2023-XXXXX fixed in 5.8. Reflected payload confirmed manually.",
    "http_exchange": "GET /wp-content/plugins/contact-form-7/readme.txt HTTP/1.1\nHost: 192.0.2.10\n\nHTTP/1.1 200 OK\n...\nStable tag: 5.7.1",
    "references": ["CVE-2023-XXXXX", "https://wpscan.com/vulnerability/..."]
  }
}
```

Severity mapping used by the parser (heuristic, operator overrides): RCE/
object injection/SQLi/auth-bypass/privilege-escalation → `critical`/`high`;
stored XSS/CSRF-to-admin/LFI → `medium`-`high`; reflected XSS/open redirect →
`medium`; info disclosure/user enumeration → `low`; version-only observations
→ `info`. Config backups and DB exports in the webroot → `high` (cleartext
credentials). Successful password attack → `critical` with the credential
pair in the rationale (and the login HTTP exchange as evidence).

Write each verified issue via the `finding-report` skill;
`parse_wpscan.py --findings wp-findings.json` pre-fills the payloads —
review, add the manual-confirmation HTTP exchange, then submit.
