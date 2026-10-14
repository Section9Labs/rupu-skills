# OWASP WSTG v4.2 test-case map → covering sub-skill

Use this to verify coverage at the end of the engagement: every ID should either
map to work actually done (asset depth `tested`+) or be explicitly recorded as
out-of-scope/not-applicable in the final notes.

## WSTG-INFO — Information Gathering

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-INFO-01 | Conduct Search Engine Discovery Reconnaissance for Information Leakage | `web-crawling` (gau/historical sources), manual dorking |
| WSTG-INFO-02 | Fingerprint Web Server | `http-probing` |
| WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage (robots.txt, sitemap, .well-known) | `web-crawling`, `content-discovery` |
| WSTG-INFO-04 | Enumerate Applications on Webserver (vhosts, ports, paths) | `http-probing`, `content-discovery` (vhost fuzzing) |
| WSTG-INFO-05 | Review Webpage Content for Information Leakage (comments, JS, source maps) | `web-crawling` (JS analysis) |
| WSTG-INFO-06 | Identify Application Entry Points | `web-crawling`, `parameter-discovery` |
| WSTG-INFO-07 | Map Execution Paths Through Application | `web-crawling` + proxy skill (`mitmproxy`/`burp-suite`/`owasp-zap`) |
| WSTG-INFO-08 | Fingerprint Web Application Framework | `http-probing` (whatweb/webanalyze) |
| WSTG-INFO-09 | Fingerprint Web Application (merged into INFO-08 in v4.2) | `http-probing`, `cms-testing` |
| WSTG-INFO-10 | Map Application Architecture (WAF, CDN, load balancer, tiers) | `http-probing` (wafw00f, CDN detection) |

## WSTG-CONF — Configuration and Deployment Management

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-CONF-01 | Test Network Infrastructure Configuration | `nuclei`, `nikto-scan` |
| WSTG-CONF-02 | Test Application Platform Configuration (sample files, debug endpoints) | `nuclei`, `nikto-scan`, `content-discovery` |
| WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information | `content-discovery` (extension fuzzing) |
| WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information | `content-discovery` (backup wordlists: `.bak`, `.old`, `~`, `.swp`, `.git`) |
| WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces | `content-discovery`, `nuclei` (panel templates) |
| WSTG-CONF-06 | Test HTTP Methods | `security-headers-testing` (OPTIONS/TRACE), `access-control-testing` (verb tampering) |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | `tls-testing`, `security-headers-testing` |
| WSTG-CONF-08 | Test RIA Cross Domain Policy (crossdomain.xml, clientaccesspolicy.xml) | `cors-testing`, `content-discovery` |
| WSTG-CONF-09 | Test File Permission | `nikto-scan`, manual via proxy |
| WSTG-CONF-10 | Test for Subdomain Takeover | `nuclei` (takeover templates), `http-probing` (CNAME review) |
| WSTG-CONF-11 | Test Cloud Storage (S3/GCS/Azure buckets) | `nuclei`, `content-discovery` |
| WSTG-CONF-12 | Test for Content Security Policy | `security-headers-testing` |

## WSTG-IDNT — Identity Management

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-IDNT-01 | Test Role Definitions | `access-control-testing` |
| WSTG-IDNT-02 | Test User Registration Process | `auth-session-testing` |
| WSTG-IDNT-03 | Test Account Provisioning Process | `auth-session-testing`, `access-control-testing` |
| WSTG-IDNT-04 | Testing for Account Enumeration and Guessable User Account | `auth-session-testing` |
| WSTG-IDNT-05 | Testing for Weak or Unenforced Username Policy | `auth-session-testing` |

## WSTG-ATHN — Authentication

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-ATHN-01 | Credentials Transported over an Encrypted Channel | `tls-testing`, proxy observation |
| WSTG-ATHN-02 | Testing for Default Credentials | `auth-session-testing`, `nuclei` (default-login templates), `cms-testing` |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism | `auth-session-testing` |
| WSTG-ATHN-04 | Testing for Bypassing Authentication Schema | `auth-session-testing`, `sqli-testing` (auth bypass payloads) |
| WSTG-ATHN-05 | Testing for Vulnerable Remember Password | `auth-session-testing` |
| WSTG-ATHN-06 | Testing for Browser Cache Weaknesses | `security-headers-testing` (Cache-Control on authed pages) |
| WSTG-ATHN-07 | Testing for Weak Password Policy | `auth-session-testing` |
| WSTG-ATHN-08 | Testing for Weak Security Question Answer | `auth-session-testing` |
| WSTG-ATHN-09 | Testing for Weak Password Change or Reset Functionalities | `auth-session-testing` (reset token analysis, host-header poisoning) |
| WSTG-ATHN-10 | Testing for Weaker Authentication in Alternative Channel | `auth-session-testing` (mobile API, legacy endpoints) |

## WSTG-ATHZ — Authorization

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-ATHZ-01 | Testing Directory Traversal / File Include | `path-traversal-testing` |
| WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema | `access-control-testing` |
| WSTG-ATHZ-03 | Testing for Privilege Escalation | `access-control-testing` |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References | `access-control-testing` |

## WSTG-SESS — Session Management

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-SESS-01 | Testing for Session Management Schema | `auth-session-testing` |
| WSTG-SESS-02 | Testing for Cookies Attributes | `auth-session-testing`, `security-headers-testing` |
| WSTG-SESS-03 | Testing for Session Fixation | `auth-session-testing` |
| WSTG-SESS-04 | Testing for Exposed Session Variables | `auth-session-testing` |
| WSTG-SESS-05 | Testing for Cross Site Request Forgery | `auth-session-testing` |
| WSTG-SESS-06 | Testing for Logout Functionality | `auth-session-testing` |
| WSTG-SESS-07 | Testing Session Timeout | `auth-session-testing` |
| WSTG-SESS-08 | Testing for Session Puzzling | `auth-session-testing` |
| WSTG-SESS-09 | Testing for Session Hijacking | `auth-session-testing`, `xss-testing` (cookie theft chain) |

## WSTG-INPV — Input Validation

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-INPV-01 | Reflected Cross Site Scripting | `xss-testing` |
| WSTG-INPV-02 | Stored Cross Site Scripting | `xss-testing` |
| WSTG-INPV-03 | HTTP Verb Tampering | `access-control-testing`, inline via proxy |
| WSTG-INPV-04 | HTTP Parameter Pollution | inline via proxy skill, `parameter-discovery` |
| WSTG-INPV-05 | SQL Injection | `sqli-testing` |
| WSTG-INPV-06 | LDAP Injection | `sqli-testing` (injection methodology applies; LDAP payload set) |
| WSTG-INPV-07 | XML Injection | `xxe-testing` |
| WSTG-INPV-08 | SSI Injection | `ssti-testing` (SSI payload set) |
| WSTG-INPV-09 | XPath Injection | `sqli-testing` (XPath payload set) |
| WSTG-INPV-10 | IMAP SMTP Injection | `command-injection-testing` (CRLF/header injection methodology) |
| WSTG-INPV-11 | Code Injection | `ssti-testing`, `command-injection-testing`, `path-traversal-testing` (LFI/RFI) |
| WSTG-INPV-12 | Command Injection | `command-injection-testing` |
| WSTG-INPV-13 | Format String Injection | `command-injection-testing` |
| WSTG-INPV-14 | Incubated Vulnerability | `xss-testing` (stored), `file-upload-testing` |
| WSTG-INPV-15 | HTTP Splitting Smuggling | `request-smuggling-testing` |
| WSTG-INPV-16 | HTTP Incoming Requests | `request-smuggling-testing` |
| WSTG-INPV-17 | Host Header Injection | `request-smuggling-testing`, `auth-session-testing` (reset poisoning) |
| WSTG-INPV-18 | Server-side Template Injection | `ssti-testing` |
| WSTG-INPV-19 | Server-Side Request Forgery | `ssrf-testing` |

## WSTG-ERRH — Error Handling

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-ERRH-01 | Testing for Improper Error Handling | all input skills (collect errors while fuzzing), `nuclei` |
| WSTG-ERRH-02 | Testing for Stack Traces | same — report leaked traces as findings |

## WSTG-CRYP — Cryptography

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-CRYP-01 | Testing for Weak Transport Layer Security | `tls-testing` |
| WSTG-CRYP-02 | Testing for Padding Oracle | `tls-testing`, `deserialization-testing` (app-level padding oracles) |
| WSTG-CRYP-03 | Sensitive Information Sent via Unencrypted Channels | `tls-testing`, proxy observation |
| WSTG-CRYP-04 | Testing for Weak Encryption | `auth-session-testing` (token analysis), manual |

## WSTG-BUSL — Business Logic

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-BUSL-01 | Test Business Logic Data Validation | `business-logic-testing` |
| WSTG-BUSL-02 | Test Ability to Forge Requests | `business-logic-testing` |
| WSTG-BUSL-03 | Test Integrity Checks | `business-logic-testing` |
| WSTG-BUSL-04 | Test for Process Timing | `business-logic-testing` (race conditions) |
| WSTG-BUSL-05 | Test Number of Times a Function Can Be Used Limits | `business-logic-testing` |
| WSTG-BUSL-06 | Testing for the Circumvention of Work Flows | `business-logic-testing` |
| WSTG-BUSL-07 | Test Defenses Against Application Misuse | `business-logic-testing` |
| WSTG-BUSL-08 | Test Upload of Unexpected File Types | `file-upload-testing` |
| WSTG-BUSL-09 | Test Upload of Malicious Files | `file-upload-testing` |

## WSTG-CLNT — Client-side

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-CLNT-01 | DOM-Based Cross Site Scripting | `xss-testing` |
| WSTG-CLNT-02 | Testing for JavaScript Execution | `xss-testing` |
| WSTG-CLNT-03 | Testing for HTML Injection | `xss-testing` |
| WSTG-CLNT-04 | Testing for Client-side URL Redirect | `open-redirect-testing` |
| WSTG-CLNT-05 | Testing for CSS Injection | `xss-testing` |
| WSTG-CLNT-06 | Testing for Client-side Resource Manipulation | `xss-testing` |
| WSTG-CLNT-07 | Testing Cross Origin Resource Sharing | `cors-testing` |
| WSTG-CLNT-08 | Testing for Cross Site Flashing (legacy) | `cors-testing` (crossdomain.xml review) |
| WSTG-CLNT-09 | Testing for Clickjacking | `security-headers-testing` |
| WSTG-CLNT-10 | Testing WebSockets | proxy skill (`mitmproxy`/`burp-suite`), `auth-session-testing` (WS auth) |
| WSTG-CLNT-11 | Testing Web Messaging | `xss-testing` (postMessage sinks) |
| WSTG-CLNT-12 | Testing Browser Storage | `xss-testing`, `auth-session-testing` (tokens in localStorage) |
| WSTG-CLNT-13 | Testing for Cross Site Script Inclusion | `xss-testing`, `cors-testing` |

## WSTG-APIT — API Testing

| ID | Test | Sub-skill(s) |
|---|---|---|
| WSTG-APIT-01 | Testing GraphQL | `parameter-discovery` (introspection), `access-control-testing`, `sqli-testing` per resolver |
