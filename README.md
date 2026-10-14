# rupu-skills

Offensive-security Agent Skills in the [agentskills.io](https://agentskills.io) `SKILL.md` format. **109 skills** organized into **7 packs** — 6 domain packs, each driven by an umbrella skill that routes to its sub-skills, plus a shared reporting pack.

Each skill is a self-contained directory under `skills/` that imports into rupu — or any agentskills.io-compatible client — like any general skill.

These skills are for authorized security assessments; scope and authorization are the operator's and the platform's responsibility, not the skill's.

## Table of contents

- [Installing](#installing)
- [How the packs work](#how-the-packs-work)
- [The packs](#the-packs)
  - [Recon](#recon-13-skills)
  - [Web application testing](#web-application-testing-28-skills)
  - [API testing](#api-testing-15-skills)
  - [Code review](#code-review-17-skills)
  - [Cloud security](#cloud-security-16-skills)
  - [Binary analysis](#binary-analysis-17-skills)
  - [Reporting (shared)](#reporting-shared-3-skills)
- [rupu data integration](#rupu-data-integration)
- [Contributing](#contributing)
- [License](#license)

## Installing

**With rupu:**

```sh
rupu fleet install                                 # materializes the stock fleet
rupu skill install Section9Labs/rupu-skills --all  # installs every skill in this repo
```

**With any other agentskills.io-compatible client:** copy a `skills/<name>/` directory into the client's skills directory.

## How the packs work

Each domain pack is pstack-style: one **umbrella skill** (same name as the pack) routes to many per-tool / per-technique **sub-skills**. The umbrella does not replace the sub-skills — it drives the phased methodology and tells you **which sub-skill to load, when, and what to feed it**.

**Load the umbrella first** (`recon`, `web-testing`, `api-testing`, `code-review`, `cloud-security`, `binary-analysis`), then load sub-skills by name as the umbrella directs. The three reporting skills are shared across every pack.

## The packs

### Recon (13 skills)

Network reconnaissance & enumeration (internal/external). Phased flow: host discovery → port scanning → service/OS detection → per-protocol enumeration → inventory normalization. Umbrella: **`recon`** — load it first.

| Skill | What it does |
|---|---|
| **`recon`** (umbrella) | Orchestrates the full phased recon flow and routes each phase to the right sub-skill |
| `host-discovery` | Layer-2/3 live-host discovery — turn scoped CIDRs into a deduplicated live-host list with fping, arp-scan, netdiscover, `nmap -sn`, zmap and nbtscan |
| `dns-recon` | DNS reconnaissance and subdomain enumeration — passive discovery (subfinder, amass, CT logs), zone transfers (dig, host, dnsrecon), brute-force and permutations |
| `masscan` | Internet-scale asynchronous TCP SYN scanning — rate-driven sweeps of huge ranges, banner grabbing, sharded/resumable scans, nmap handoff |
| `rustscan` | Very fast port discovery — all 65k TCP ports in seconds, piping open ports straight into Nmap with the `--` passthrough |
| `naabu` | Fast SYN/CONNECT port discovery with ProjectDiscovery's naabu — pipeline-friendly sweeps, CDN awareness, built-in `-nmap-cli` handoff |
| `nmap` | Full-capability Nmap methodology — host discovery, TCP/UDP scanning, service/version and OS detection, NSE scripting, timing/evasion, structured XML output |
| `smb-enum` | SMB / MSRPC / NetBIOS enumeration with enum4linux-ng, smbmap, smbclient, rpcclient and nbtscan — null/guest/authenticated sessions, share walking, RID cycling, signing and SMBv1 checks |
| `ldap-ad-enum` | LDAP / Active Directory enumeration with ldapsearch, windapsearch and bloodhound-ce-python — rootDSE, object dumps, UAC-bit filters for kerberoastable/AS-REP/delegation accounts, LAPS/gMSA |
| `snmp-enum` | SNMP enumeration — brute community strings with onesixtyone, walk high-value OIDs with snmpwalk/snmpbulkwalk/braa, snmp-check dumps, v3 users, write-community tests |
| `nfs-enum` | Enumerate and loot NFS — rpcinfo/showmount export discovery, export-ACL reading, mounting v3/v4, UID spoofing and `no_root_squash` exploitation |
| `ike-scan` | Discover, fingerprint and attack IPsec/IKE VPN gateways — transform enumeration, Vendor-ID and backoff fingerprinting, aggressive-mode PSK hash capture and offline cracking |
| `netexec` | Credentialed sweep, password spraying, and post-auth enumeration with NetExec (nxc) across SMB/LDAP/WinRM/MSSQL/SSH/FTP/RDP/WMI/VNC/NFS |

### Web application testing (28 skills)

End-to-end web app assessment following OWASP WSTG v4.2. Umbrella: **`web-testing`** — load it first.

| Skill | What it does |
|---|---|
| **`web-testing`** (umbrella) | Phased WSTG v4.2 flow from scope intake and recon through config, auth/session, authorization, input-validation, business-logic and client-side testing, routing each phase to a sub-skill |
| `mitmproxy` | Intercept, inspect, modify, capture, and replay HTTP(S)/WebSocket traffic with mitmproxy/mitmdump/mitmweb; automate rewriting with Python addons |
| `burp-suite` | Drive Burp Suite (Pro/Community) as the web workbench — Proxy/Repeater tampering, Intruder fuzzing, Pro crawl-and-audit, Collaborator OOB confirmation |
| `owasp-zap` | Drive OWASP ZAP as the open-source DAST and interception proxy — daemon mode + REST API, Automation Framework, packaged Docker scan scripts |
| `http-probing` | Live-host triage and technology fingerprinting with httpx, whatweb, and webanalyze — turn raw host lists into a probed inventory of live web endpoints |
| `web-crawling` | Map a target's full URL and attack surface — active crawling (katana, hakrawler, gospider) plus passive URL harvesting (gau, waybackurls), normalized and deduped |
| `content-discovery` | Wordlist-driven discovery of hidden directories, files, and vhosts with ffuf, feroxbuster, dirsearch, and gobuster |
| `parameter-discovery` | Discover hidden/unlinked HTTP parameters with arjun as primary fuzzer, x8 for high-rate fuzzing, and mined per-target wordlists |
| `nuclei` | Template-driven vulnerability and misconfiguration scanning with ProjectDiscovery nuclei — known CVEs, exposures, default creds, tech fingerprinting |
| `nikto-scan` | Fast baseline web-server misconfiguration and known-issue sweep with nikto plus wapiti as the active-DAST companion |
| `cms-testing` | Identify and attack CMS platforms (WordPress, Joomla, Drupal, generic) with wpscan, joomscan, droopescan, cmsmap, and CMSeeK |
| `tls-testing` | Assess TLS/SSL configuration — protocols, ciphers, certificate chain, key exchange, and named vulnerabilities (Heartbleed, ROBOT, DROWN, CCS injection, Ticketbleed…) |
| `security-headers-testing` | Review HTTP security headers and cookie flags — CSP, HSTS, X-Frame-Options (with working clickjacking PoC), X-Content-Type-Options, Referrer-Policy |
| `auth-session-testing` | Authentication and session management testing (WSTG-ATHN/SESS/IDNT) — enumeration, brute force with hydra and ffuf, reset flaws, JWT attacks with jwt_tool |
| `access-control-testing` | Broken access control — IDOR/BOLA, BFLA, horizontal/vertical privilege escalation, forced browsing, mass assignment, header/path authz bypass |
| `sqli-testing` | Detect, confirm, and exploit SQL injection across GET/POST/JSON/header/cookie parameters — manual probes first, then sqlmap end to end |
| `xss-testing` | Reflected, stored, DOM-based and blind XSS — kxss/Gxss reflection discovery, dalfox pipeline scanning, XSStrike context analysis, manual break-outs |
| `command-injection-testing` | OS command injection — manual separator/blind/OOB probing, commix automation to pseudo-shell/reverse shell, interactsh for blind confirmation |
| `xxe-testing` | XML External Entity injection in any XML-parsing endpoint (SOAP, SAML, SVG/DOCX uploads) — in-band file read, `php://filter`, blind/OOB exfiltration |
| `ssti-testing` | Server-Side Template Injection end to end — polyglot probing, differential engine fingerprinting (Jinja2/Twig/Freemarker/…), per-engine exploitation |
| `path-traversal-testing` | Path traversal and LFI/RFI — encoded `../` sequences, escalating PHP LFI to RCE via wrappers, log poisoning and session techniques |
| `deserialization-testing` | Insecure deserialization across Java, .NET, PHP, and Python — spot serialized blobs in cookies/params/headers/uploads and confirm sinks |
| `ssrf-testing` | Server-Side Request Forgery — find URL-consuming inputs, confirm with interactsh OOB callbacks, pivot to internal ranges and cloud metadata, defeat filters |
| `open-redirect-testing` | Open redirect and CRLF/response-splitting — enumerate redirect params, fire whitelist-bypass payloads, distinguish header vs client-side redirects |
| `cors-testing` | CORS misconfiguration — reflected-origin + credentials combos, null-origin trust, prefix/suffix/unescaped-dot regex bypasses |
| `request-smuggling-testing` | HTTP request smuggling / desync (CL.TE, TE.CL, TE.TE, H2 downgrades), Host header attacks, and web cache poisoning/deception |
| `business-logic-testing` | Manual, reasoning-driven business-logic testing — price/quantity/coupon tampering, forged/replayed requests, race conditions, workflow step-skipping |
| `file-upload-testing` | Unrestricted/malicious file upload — extension/MIME/magic-byte bypasses, webshells, `.htaccess`/web.config tricks, SVG stored-XSS/XXE, zip-slip |

### API testing (15 skills)

REST/GraphQL/gRPC API testing structured around the OWASP API Security Top 10 (2023). Umbrella: **`api-testing`** — load it first.

| Skill | What it does |
|---|---|
| **`api-testing`** (umbrella) | End-to-end API assessment flow — routes spec discovery, surface scanning, authentication, authorization and injection phases to sub-skills |
| `api-spec-discovery` | Discover an API's machine-readable definition (OpenAPI/Swagger, Postman, GraphQL schema, OIDC metadata) and normalize every operation into a ready-to-send request set |
| `api-param-discovery` | Discover hidden/undocumented parameters an API accepts but does not advertise, using arjun across query strings and POST/JSON/XML bodies |
| `api-endpoint-brute` | Brute-force hidden API routes with kiterunner (`.kite` request corpora) and ffuf as a plain-path fallback when no complete spec exists |
| `api-fuzzing` | Spec-driven HTTP fuzzing with ffuf — paths, parameter names/values, methods, and JSON bodies generated from a parsed OpenAPI request set |
| `api-nuclei` | Scan an API surface for known exposures, misconfigurations, leaked tokens, CVEs and injectable parameters with nuclei v3 templates plus its DAST fuzzing mode |
| `api-broken-auth` | OWASP API2:2023 Broken Authentication — API key placement/enforcement/leakage, credential stuffing and spraying, enumeration, reset/OTP abuse, session tokens |
| `oauth-oidc-testing` | OAuth 2.0 / OpenID Connect flow abuse — redirect_uri validation, state/CSRF, PKCE enforcement, scope escalation, implicit-flow token leakage |
| `jwt-attacks` | Attack JWT authentication with jwt_tool — `alg:none`, null signatures, RS256→HS256 key confusion, JWKS spoofing/injection, `kid` abuse, weak-HMAC cracking |
| `api-authorization` | Multi-identity differential testing — BOLA/IDOR (API1), BFLA (API5), and BOPLA mass-assignment / excessive-data-exposure (API3) |
| `api-injection` | Injection against API parameters — SQL, NoSQL, OS command, SSTI, LDAP/XPath, XML/XXE — delivered through JSON bodies, query/path params, and headers |
| `api-ssrf` | SSRF in HTTP APIs (API7:2023) — locate URL-consuming sinks (webhooks, import-from-URL, renderers), prove server-side fetches via out-of-band callbacks, pivot |
| `api-resource-consumption` | API4:2023 Unrestricted Resource Consumption and API6:2023 sensitive business flows — prove or disprove rate limits, bypass limiters via header rotation |
| `graphql-testing` | End-to-end GraphQL testing — engine fingerprinting with graphw00f, misconfig audit with graphql-cop, schema recovery via introspection or clairvoyance |
| `grpc-testing` | Enumerate and attack gRPC services with grpcurl — reflection-based discovery, proto/protoset-driven invocation, metadata (auth) manipulation |

### Code review (17 skills)

Authorized security code review — SAST, secret scanning, SCA/SBOM, taint analysis. Umbrella: **`code-review`** — load it first.

| Skill | What it does |
|---|---|
| **`code-review`** (umbrella) | Triage the repo, then route to the right SAST, secret-scanning, SCA/SBOM and taint-analysis sub-skills; normalize everything to one deduplicated finding set |
| `semgrep` | Semgrep (OSS CLI) static analysis across languages — registry rulesets, custom pattern and taint rules, SARIF/JSON output |
| `bandit` | PyCQA Bandit for Python SAST — recursive scans, baselines/thresholds, the full Bxxx test catalog, noise suppression |
| `gosec` | gosec for Go — rule (Gxxx) and severity/confidence selection, `#nosec` handling, SARIF/JSON output |
| `brakeman` | Brakeman static analysis of Ruby on Rails apps — warning types/confidence/user-input paths, ignore tuning, JSON+SARIF output |
| `njsscan` | njsscan (MobSF's semgrep+regex SAST) for Node.js/JavaScript — JSON/SARIF output, `.njsscan` configs, `--missing-controls` |
| `find-sec-bugs` | SpotBugs + Find Security Bugs for compiled Java/Kotlin/Scala/Groovy bytecode — injection, XXE, deserialization, SSRF, XSS, weak crypto, hardcoded secrets |
| `codeql` | Deep interprocedural analysis with the GitHub CodeQL CLI — build a database, run security suites or custom taint-tracking queries, parse SARIF source→sink flows |
| `taint-analysis` | Manual + tool-assisted source-to-sink methodology — ripgrep sink-pattern packs, backwards tracing to untrusted sources, sanitizer checks |
| `gitleaks` | Gitleaks v8+ secret scanning of git history and filesystems — fast regex + entropy over every commit for leaked credentials, keys and tokens |
| `trufflehog` | TruffleHog v3 — 800+ detectors that live-verify leaked credentials against each provider's API; scans git history, GitHub orgs, filesystems, S3/GCS, Docker images |
| `dependency-check` | OWASP Dependency-Check SCA — identify third-party dependencies across ecosystems, match CPEs, surface known CVEs from the NVD |
| `osv-scanner` | Google OSV-Scanner v2 against repos, lockfiles, SBOMs and container images, matched to the OSV.dev vulnerability database |
| `grype-syft` | Generate SBOMs with Anchore Syft and scan them for known vulnerabilities with Grype |
| `cargo-audit` | cargo-audit (RustSec) over `Cargo.lock` — or compiled binaries via `cargo audit bin` — for vulnerable, unmaintained, unsound and yanked crates |
| `retire-js` | Retire.js detection of known-vulnerable JS libraries — including bundled, minified or CDN-vendored front-end libs lockfile-based SCA misses |
| `sarif-triage` | Normalize, deduplicate and triage SARIF 2.1.0 and native-JSON output from any SAST/SCA/secret scanner into one unified, prioritized finding set |

### Cloud security (16 skills)

Offensive cloud assessment across AWS, Azure (incl. Entra ID) and GCP — the credential → identity → posture → enumeration → privesc → loot loop. Umbrella: **`cloud-security`** — load it first.

| Skill | What it does |
|---|---|
| **`cloud-security`** (umbrella) | Runs the credential→identity→posture→enumeration→privesc→loot→new-credential loop and routes each phase to the right sub-skill |
| `cloud-credential-enumeration` | Discover, classify, validate and identity-map cloud credentials (AWS keys, Azure SPs/JWTs/SAS, GCP SA keys and tokens), then enumerate what each can become |
| `aws-enumeration` | Exhaustive manual AWS enumeration with the aws CLI and enumerate-iam — identity/STS triage, permission brute-forcing, full multi-region service sweep |
| `azure-enumeration` | Azure resource-plane (ARM) enumeration with the az CLI and ARM REST — VMs, storage, Key Vaults, App Services, AKS, SQL, automation accounts |
| `azure-entra-id` | Attack the Microsoft Entra ID identity plane — tenant/user recon, directory enumeration with ROADtools/AzureHound/AADInternals, token acquisition with roadtx |
| `gcp-enumeration` | Exhaustive GCP resource-plane enumeration with gcloud/gsutil and REST — IAM policies, `testIamPermissions`, per-project sweeps of Compute and friends |
| `cloud-storage-exposure` | Discover, permission-test and exploit exposed object storage across S3, Azure Blob and GCS — name permutation, access matrix, write tests, bulk exfiltration |
| `metadata-ssrf-pivot` | Turn an SSRF/RCE/file-read foothold on a cloud workload into cloud credentials via the metadata service (AWS IMDS, ECS/EKS, Azure IMDS, GCP metadata) |
| `cloud-privilege-escalation` | Cross-cloud IAM privilege-escalation technique catalog for AWS, Azure and GCP with exact exploit commands per method |
| `pacu` | Pacu (Rhino Security Labs' AWS exploitation framework) end to end — sessions, credential import, `iam__privesc_scan` detection AND exploitation, persistence, loot |
| `pmapper` | Map AWS IAM into an attack graph with PMapper and extract ranked privilege-escalation paths between principals |
| `prowler` | Prowler (v4/v5) posture scans across AWS, Azure, GCP and Kubernetes — OCSF JSON parsing, exploitable FAIL findings as work units |
| `scoutsuite` | ScoutSuite (NCC Group) multi-cloud audits across AWS, Azure and GCP (plus Aliyun/OCI) — danger/warning finding extraction |
| `cloudsploit` | Aqua's open-source CloudSploit scanner against AWS, Azure, GCP and OCI — misconfiguration enumeration, FAIL findings split into exploit-ready work units |
| `cloudfox` | BishopFox CloudFox attack-surface enumeration — aws all-checks (endpoints, instances, buckets, secrets, permissions, role-trusts) plus Azure modules and loot output |
| `steampipe` | Query live AWS/Azure/GCP APIs as SQL with Steampipe for offensive attack-surface mapping, plus Powerpipe CIS/NIST benchmarks |

### Binary analysis (17 skills)

Binary analysis / reverse engineering / exploitation — from first-contact triage through working exploitation primitives. Umbrella: **`binary-analysis`** — load it first.

| Skill | What it does |
|---|---|
| **`binary-analysis`** (umbrella) | End-to-end flow for taking unknown binaries (ELF, PE, Mach-O, raw firmware) from first contact through triage, static and dynamic analysis, to exploitation |
| `binary-triage` | First-contact triage of an unknown binary — format/arch/linkage, strings and imports mining, ELF structure |
| `binary-protections` | Read a binary's exploit mitigations (NX, canary, PIE, RELRO, FORTIFY, ASLR, CET/CFI, PE DEP/CFG/SafeSEH) and translate each into an exploitation-plan decision |
| `dynamic-tracing` | Observe library calls and syscalls with ltrace and strace — follow forks, decode fds, spot attacker-reachable file/network/exec behavior |
| `radare2` | Interactive and scripted RE with radare2/rizin and r2pipe — analysis, disassembly, xrefs, strings/imports/protections, gadget search, visual graph mode |
| `ghidra-headless` | Scriptable bulk static RE with Ghidra's headless analyzer — import binaries or firmware trees, run postScripts to export function lists and decompiled C |
| `binwalk-firmware` | Carve, extract and triage firmware images with binwalk — signature/entropy scans, recursive extraction, filesystem unpacking, rootfs triage |
| `qiling-unicorn` | Emulate binaries you cannot or should not run natively with the Qiling framework, plus raw CPU emulation of lifted routines with Unicorn |
| `vuln-classes` | Identify common memory-safety and logic vulnerability classes — stack/heap overflow, UAF/double-free, format string, integer bugs, off-by-one |
| `fuzzing` | Coverage-guided fuzzing with AFL++, honggfuzz and libFuzzer — one harness for all three engines, sanitizers, CmpLog, corpus minimization, multi-core campaigns |
| `angr` | Symbolic/concolic execution with angr — solve for inputs that reach/avoid a state, recover license checks, detect unconstrained (hijackable) states |
| `pwntools` | Exploit development with pwntools — context/ELF/libc setup, tubes, packing and cyclic offsets, ROP objects, shellcraft, gdb integration, fmtstr helper |
| `gdb-debugging` | Dynamic analysis and exploit dev with gdb plus GEF and pwndbg — cyclic-pattern offsets, memory/registers/GOT/heap inspection, breakpoints and watchpoints |
| `rop-chains` | Build ROP chains to defeat NX/ASLR — ROPgadget/ropper/r2 gadget discovery, ret2plt leaks, ret2libc, SROP, ret2dlresolve, one_gadget, stack pivots |
| `format-string-exploitation` | Weaponize printf-family format-string bugs — find the offset with `%p` probes, arbitrary read for canary/PIE/libc leaks, arbitrary write via `%n` variants |
| `heap-exploitation` | Exploit the glibc ptmalloc2 heap — tcache poisoning/dup, fastbin dup, unsorted-bin leaks, the Houses, hook overwrites pre-2.34 and FSOP/exit-handler targets |
| `libc-identification` | Identify the exact remote glibc build from leaked runtime addresses (libc-database / libc.rip), compute the base, resolve system/str_bin_sh/one_gadget offsets |

### Reporting (shared) (3 skills)

Shared across every pack — the rupu data-integration layer. No umbrella; every domain umbrella imports these by name.

| Skill | What it does |
|---|---|
| `finding-report` | Turn raw assessment evidence into one complete, reproducible security finding recorded with rupu's `findings.report` tool — title, ownership, CVSS v3.1 severity, root cause, impact, evidence, replication |
| `work-units` | Shared results-normalizer and work-unit splitter — converts heterogeneous tool output (nmap XML, naabu/httpx JSONL, OpenAPI specs, SARIF 2.1.0, Prowler OCSF, generic JSON/JSONL) into one clean JSON array of work units |
| `coverage-assets` | Record every asset the fleet touches (hosts, services, routes, endpoints, cloud resources, files, binaries) into rupu's engagement asset ledger with typed coordinates and depth rungs; track assessed-vs-gap coverage |

## rupu data integration

Every pack follows the same handoff contract, owned by the three shared reporting skills:

- **Work units** (`work-units`) — every parse/handoff step ends by emitting a clean JSON array of `{id, title, targets, hints}` work units. A rupu workflow reads it with `read_file` and fans out with `for_each:`; a lead agent fans out with `dispatch`, one subagent per unit. The next phase consumes stable units, never raw scanner output.
- **Coverage** (`coverage-assets`) — every asset touched is recorded with `assets.mark`, with correct kinds, typed coordinates and depth rungs, so assessed-vs-gap coverage is explicit state rather than memory.
- **Findings** (`finding-report`) — every verified issue is recorded with `findings.report` as a complete, reproducible finding.

## Contributing

New skills follow the [agentskills.io](https://agentskills.io) `SKILL.md` format: a self-contained directory under `skills/<name>/` with YAML frontmatter (`name`, `description`) and the skill body. Sub-skills belong to a pack and are routed from that pack's umbrella skill — add the routing entry to the umbrella when contributing a new sub-skill.

## License

[Apache-2.0](LICENSE).
