# Bandit test catalog (Bxxx) by vulnerability class

Severity/confidence shown are Bandit's defaults. Each entry: id, what it
matches, a minimal vulnerable snippet, and what to check when triaging.
Docs: https://bandit.readthedocs.io/en/latest/plugins/

## Code execution

### B102 — exec_used (MED/HIGH, CWE-78)
```python
exec(user_supplied)            # direct code injection if input reaches it
```
Triage: constant strings are style issues; any variable argument is a
lead. Trace the variable.

### B307 — eval (MED/HIGH, CWE-78)
```python
result = eval(request.args["expr"])
```
`ast.literal_eval` is the safe replacement; flag any `eval` on non-literal
input. Classic bypass surface even with "sandboxing" attempts
(`eval(x, {"__builtins__": {}})` is bypassable via `().__class__` chains).

### B202 — tarfile_unsafe_members (HIGH/HIGH, CWE-22)
```python
tarfile.open(path).extractall(dest)   # path traversal via ../ members
```
Exploit: craft a tar with `../../home/user/.ssh/authorized_keys` member.

## Shell / command injection (B6xx)

### B602 — subprocess_popen_with_shell_equals_true (HIGH/HIGH, CWE-78)
```python
subprocess.Popen(f"ping {host}", shell=True)
subprocess.call("tar xf " + fname, shell=True)
```
The flagship finding. If the command string contains ANY variable, trace
it. PoC payloads: `; id`, `$(id)`, `` `id` ``, `| id`. Constant string +
shell=True is LOW severity (B602 still fires, lower sev).

### B603 — subprocess_without_shell_equals_true (LOW/HIGH, CWE-78)
```python
subprocess.run(["git", "clone", user_url])
```
No shell metachars, but argument injection still applies: `user_url =
"--upload-pack=touch${IFS}/tmp/pwn"` style flags, or binaries that spawn
shells (`ssh -oProxyCommand=`). Check argv[0] controllability too.

### B604 — any_other_function_with_shell_equals_true (MED/LOW, CWE-78)
Any non-subprocess callable invoked with `shell=True` — catches wrappers
(`sh`, `fabric`, custom helpers). Configurable via the
`any_other_function_with_shell_equals_true` config key.

### B605 — start_process_with_a_shell (os.system family) (LOW–HIGH/HIGH, CWE-78)
```python
os.system("convert %s out.png" % infile)
os.popen("du -sh " + path)
```
Severity scales with whether the string is dynamic. Same PoC payloads as
B602. Also matches `commands.getoutput` (py2).

### B606 — start_process_with_no_shell (LOW/MED, CWE-78)
`os.execv`, `os.spawnv*` etc. — argv injection only.

### B607 — start_process_with_partial_path (LOW/HIGH, CWE-78)
```python
subprocess.run(["backup.sh"])     # resolved via PATH — hijackable
```
Interesting when PATH or CWD is attacker-influenced (cron, setuid
helpers, extracted archives).

### B608 — hardcoded_sql_expressions (MED/LOW-MED, CWE-89)
```python
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
cur.execute(f"DELETE FROM t WHERE id = {uid}")
q = "SELECT " + cols + " FROM " + table
```
High false-positive rate (fires on any SQL-looking string built with
%/+/f-string/.format) but every true positive is SQLi. Verify: is the
interpolated value user input, and is there no parameterization layer?
Hand confirmed candidates to semgrep taint / codeql.

### B609 — linux_commands_wildcard_injection (HIGH/MED, CWE-78)
```python
os.system("tar czf backup.tgz *")      # in attacker-writable dir
```
Exploit: create files named `--checkpoint=1`,
`--checkpoint-action=exec=sh payload.sh` in the globbed directory.

## Deserialization

### B301 — pickle (MED/HIGH, CWE-502)
```python
obj = pickle.loads(request.data)       # RCE via __reduce__
```
Matches pickle/cPickle/dill/shelve/pandas.read_pickle. Any
attacker-reachable loads == RCE:
```python
class P:  # PoC gadget
    def __reduce__(self): return (os.system, ("id",))
```

### B302 — marshal (MED/HIGH, CWE-502)
`marshal.loads` of untrusted bytecode — code exec on load/exec.

### B403 / B404 — import_pickle / import_subprocess (LOW/HIGH)
Import-level breadcrumbs. Not findings themselves; use them to locate
files worth manual review when the usage tests miss wrappers.

### B506 — yaml_load (MED/HIGH, CWE-502)
```python
cfg = yaml.load(f)                     # Loader defaults to unsafe (<5.1)
cfg = yaml.load(f, Loader=yaml.Loader) # explicit unsafe
```
Safe: `yaml.safe_load` or `Loader=SafeLoader` (Bandit suppresses those).
RCE PoC: `!!python/object/apply:os.system ["id"]`.

## Weak crypto & hashing

### B303 / B324 — md5/sha1 and hashlib "new" (MED–HIGH/HIGH, CWE-327)
```python
hashlib.md5(password.encode()).hexdigest()
hashlib.new("sha1", data)
```
B324 is the modern plugin; HIGH severity when `usedforsecurity=True`
(the default). Triage by use: password storage / signatures / tokens =
real; cache keys and ETags = `# nosec B324` or
`usedforsecurity=False`.

### B304 / B305 — weak ciphers / modes (MED–HIGH/HIGH, CWE-327)
DES, 3DES, RC4, Blowfish, XOR "crypto"; ECB mode via pycrypto/
cryptography. ECB on structured plaintext leaks patterns; RC4/DES are
breakable.

### B505 — weak_cryptographic_key (MED–HIGH/HIGH, CWE-326)
RSA < 2048, DSA < 2048, EC < 224 bits in key-generation calls.

### B311 — random (LOW/HIGH, CWE-330)
```python
token = "".join(random.choices(string.ascii_letters, k=32))  # predictable
```
Only a finding when the value is a secret (session token, reset code,
API key) — Mersenne Twister state recovers from 624 outputs. Fix:
`secrets` module. Otherwise skip (`-s B311`).

## TLS / SSL

### B501 — request_with_no_cert_validation (HIGH/HIGH, CWE-295)
```python
requests.get(url, verify=False)
httpx.Client(verify=False)
```
MITM-able. Check whether url carries credentials/tokens.

### B502 — ssl_with_bad_version (HIGH/HIGH, CWE-327)
`ssl_version=ssl.PROTOCOL_SSLv3` / TLSv1 / TLSv1.1 in `ssl.wrap_socket`,
pyOpenSSL contexts.

### B503 — ssl_with_bad_defaults (MED/MED)
Function **parameters defaulting** to bad SSL versions.

### B504 — ssl_with_no_version (LOW/MED)
`ssl.wrap_socket()` without `ssl_version` — pre-3.6 negotiates poorly.

### B323 — unverified_context (MED/HIGH, CWE-295)
`ssl._create_unverified_context()` passed to urllib/ftplib/etc.

## Hardcoded secrets

### B105 / B106 / B107 — hardcoded_password_{string,funcarg,default} (LOW/MED, CWE-259)
```python
PASSWORD = "hunter2"                       # B105
connect(user="svc", password="hunter2")    # B106
def login(user, password="changeme"): ...  # B107
```
Heuristic (variable-name based) — expect FPs on `password=""` sentinels
and test fixtures, and FNs on anything not named like a password. Pair
with dedicated secret scanners for history and entropy coverage. Every
true hit: test the credential against live services in scope.

## Web frameworks

### B201 — flask_debug_true (HIGH/MED, CWE-94)
```python
app.run(debug=True)        # Werkzeug debugger => interactive RCE console
```
If reachable in a deployed service, the Werkzeug console PIN is often
derivable (public technique using /proc and MAC); straight RCE.

### B701 — jinja2_autoescape_false (HIGH/HIGH, CWE-94)
```python
Environment(loader=loader)                    # autoescape defaults False
Environment(loader=loader, autoescape=False)
```
XSS by default; if templates themselves are user-influenced, SSTI → RCE
(`{{ cycler.__init__.__globals__.os.popen('id').read() }}`).

### B702 — use_of_mako_templates (MED/HIGH)
Mako has no autoescape; every `${x}` is raw output.

### B703 — django_mark_safe (MED/HIGH, CWE-80)
`mark_safe(user_html)` / `format_html` misuse → XSS.

### B610 / B611 — django_extra_used / django_rawsql_used (MED/MED, CWE-89)
`QuerySet.extra(where=[...])`, `RawSQL(...)` with concatenated input.

## XML / XXE (B31x usage, B40x–B41x imports)

### B313–B320 (MED/HIGH, CWE-20)
- B313 xml.etree.cElementTree, B314 xml.etree.ElementTree
- B315 xml.sax.expatreader, B316 xml.dom.expatbuilder
- B317 xml.sax, B318 xml.dom.minidom, B319 xml.dom.pulldom
- B320 lxml.etree (removed in newer Bandit; lxml now resolves no
  external entities by default)

```python
tree = xml.etree.ElementTree.parse(upload)   # billion laughs / XXE DoS
doc = xml.dom.minidom.parseString(body)
```
stdlib parsers: entity-expansion DoS always; external-entity file read
depends on parser/feature flags. Fix: `defusedxml`. Related imports:
B405–B411; B411 xmlrpclib (also pickle-capable), B412 httpoxy/cgi.

## Filesystem & permissions

### B306 — mktemp_q (MED/HIGH, CWE-377)
```python
path = tempfile.mktemp()      # TOCTOU: attacker pre-creates/symlinks path
open(path, "w").write(data)
```
Fix: `tempfile.mkstemp()` / `NamedTemporaryFile`. Exploit: symlink the
predicted name to a victim-writable target.

### B108 — hardcoded_tmp_directory (MED/MED, CWE-377)
`"/tmp/out.log"` literals — symlink attacks on shared hosts.

### B103 — set_bad_file_permissions (MED–HIGH/HIGH, CWE-732)
`os.chmod(p, 0o777)` / world-writable or setuid bits.

## Network / protocol

### B104 — hardcoded_bind_all_interfaces (MED/MED, CWE-605)
`app.run(host="0.0.0.0")`, `s.bind(("0.0.0.0", 8080))` — exposure, note
it alongside what the service does.

### B310 — urllib_urlopen (MED/HIGH, CWE-22)
```python
urllib.request.urlopen(user_url)    # file:// and custom schemes accepted
```
SSRF + local file read via `file:///etc/passwd`. Trace the URL source.

### B312 — telnetlib, B321 — ftplib, B401/B402 imports (HIGH/HIGH, CWE-319)
Cleartext protocols; grab-creds-on-the-wire issues. B508/B509: SNMP v1/v2
and weak crypto in pysnmp.

## Low-signal / usually skipped

- **B101 assert_used** — asserts vanish under `python -O`; only report if
  an assert enforces authz/validation in production code paths.
- **B110 try_except_pass / B112 try_except_continue** — swallowed
  exceptions; context-dependent.
- **B113 request_without_timeout** — DoS hygiene.
- **B322 input()** — Python 2 only (eval'd input).

Typical skip set for triage: `-s B101,B110,B112,B311,B404,B403,B405`.

## Suppression syntax

```python
subprocess.run(FIXED, shell=True)  # nosec B602 -- constant, reviewed 2024-05
yaml.load(f, Loader=TrustedLoader)  # nosec B506
```
Scoped (`# nosec B602`) suppresses only that test on that line; bare
`# nosec` suppresses everything — treat bare nosec near user input as a
finding in itself. `--ignore-nosec` makes Bandit report suppressed lines
anyway: run it once per engagement to audit the suppressions.
