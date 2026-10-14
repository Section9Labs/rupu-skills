# Sub-skill index (load by name)

## Proxies / DAST platforms (pick one in Phase 1)

| Skill | What it's for |
|---|---|
| `mitmproxy` | Scriptable interception proxy (mitmproxy/mitmdump/mitmweb) — addons, flow filtering, replay; best for headless/automated tampering. |
| `burp-suite` | Burp proxy workflow — Repeater, Intruder, Collaborator OOB, extensions; best for deep manual testing. |
| `owasp-zap` | ZAP proxy + active scanner, API/daemon mode, automation framework; free DAST pass alongside manual work. |

## Recon / mapping (Phase 2)

| Skill | What it's for |
|---|---|
| `http-probing` | httpx/whatweb/webanalyze liveness + tech fingerprinting, wafw00f WAF detection; emits live-sites work units. |
| `web-crawling` | katana/gau/hakrawler active+historical URL harvesting, JS endpoint extraction; emits route work units. |
| `content-discovery` | ffuf/feroxbuster directory, file, backup and vhost brute-force with recursion; emits route work units. |
| `parameter-discovery` | arjun hidden GET/POST/JSON parameter discovery per route; emits route+param work units. |

## Config / crypto (Phase 3)

| Skill | What it's for |
|---|---|
| `nuclei` | Template-driven known-issue sweep: CVEs, exposures, misconfigs, default creds, takeovers; emits confirmation work units. |
| `nikto-scan` | Classic web-server misconfiguration / dangerous-file scanner. |
| `cms-testing` | WordPress/Joomla/Drupal etc.: wpscan, droopescan, plugin/theme/user enumeration and known-vuln checks. |
| `tls-testing` | testssl.sh/sslyze: protocols, ciphers, cert chain, HSTS, padding-oracle (WSTG-CRYP). |
| `security-headers-testing` | CSP/HSTS/XFO analysis, cookie flags, clickjacking PoC, cache-control, CORP/COOP/COEP. |

## Auth / session / authorization (Phases 4–5)

| Skill | What it's for |
|---|---|
| `auth-session-testing` | Credential attacks (hydra/ffuf), enumeration, lockout, JWT attacks, session fixation/cookies/CSRF, password reset abuse. |
| `access-control-testing` | IDOR/BOLA, BFLA, horizontal/vertical privesc via multi-session differential replay. |

## Input validation / server-side trust (Phase 6)

| Skill | What it's for |
|---|---|
| `sqli-testing` | SQL/NoSQL injection: manual detection + sqlmap through to `--os-shell`/`--dump`. |
| `xss-testing` | Reflected/stored/DOM XSS, sink analysis, CSP bypass, dalfox. |
| `command-injection-testing` | OS command injection: separators, blind time/OOB detection, filter bypass. |
| `xxe-testing` | XML external entity: in-band, error-based, blind OOB exfil, parameter entities. |
| `ssti-testing` | Server-side template injection: engine identification → sandbox escape → RCE. |
| `path-traversal-testing` | Traversal/LFI/RFI, wrapper tricks, log poisoning, LFI→RCE chains. |
| `deserialization-testing` | Java/PHP/.NET/Python insecure deserialization, ysoserial/phpggc gadget chains. |
| `ssrf-testing` | SSRF: internal reach, cloud metadata, protocol smuggling, blind via OOB callbacks. |
| `open-redirect-testing` | Open redirect server- and client-side, filter bypass payloads, OAuth chain impact. |
| `cors-testing` | CORS misconfiguration: origin reflection, null origin, credentialed cross-origin reads. |
| `request-smuggling-testing` | CL.TE/TE.CL/HTTP2 desync, host-header injection, web-cache poisoning/deception. |

## Logic / uploads (Phase 7)

| Skill | What it's for |
|---|---|
| `business-logic-testing` | Workflow circumvention, request forging, race conditions, limit abuse (WSTG-BUSL). |
| `file-upload-testing` | Upload abuse: extension/MIME bypass, polyglots, webshells, stored-path attacks. |

## Shared rupu skills (every phase)

| Skill | What it's for |
|---|---|
| `work-units` | Canonical work-unit array splitter/normalizer — hand every fan-out array to it. |
| `coverage-assets` | Recording assets with `assets.mark` and the depth ladder — the coverage ledger. |
| `finding-report` | Writing a complete `findings.report` finding (evidence, exchange, classification). |
