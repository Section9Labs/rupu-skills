# Python: sources, sinks, sanitizers, ripgrep patterns

## Sources

| Framework | Expressions |
|---|---|
| Flask | `request.args`, `request.form`, `request.values`, `request.get_json()`, `request.json`, `request.data`, `request.headers`, `request.cookies`, `request.files` (`.filename`!), route params `<name>` |
| Django | `request.GET`, `request.POST`, `request.body`, `request.META` (headers), `request.COOKIES`, `request.FILES`, URLconf capture groups, form `cleaned_data` (validated — judge per field) |
| FastAPI/Starlette | path/query/body params (typed — `int`/`UUID` annotations are sanitizers; `str` is not), `request.headers`, `request.cookies` |
| Generic | `sys.argv`, `input()`, `os.environ` (when set by less-trusted layer), `socket.recv`, file reads from upload dirs, Celery/queue task args, DB reads of user-written columns (second-order) |

## Sinks by class

### SQL injection
```
rg -n '\.execute(many)?\(\s*f["\x27]' -g '*.py'
rg -n '\.execute(many)?\([^,)]*(\+|%[\s(]|\.format\()' -g '*.py'
rg -n '\.(raw|extra)\(|text\(\s*f["\x27]|session\.execute\(\s*f' -g '*.py'
rg -n 'cursor\.mogrify|sqlalchemy\.text\(' -g '*.py'
```
Sinks: DB-API `cursor.execute/executemany` first arg; Django `Model.objects.raw()`,
`QuerySet.extra()`, `connection.cursor().execute()`; SQLAlchemy `text()`,
`engine.execute()`, `session.execute()` with built strings; `order_by(user)`
with user-supplied column names.
Sanitizers: second-arg parameter tuples/dicts; ORM querysets with kwargs;
allowlist dict for identifiers.

### Command injection
```
rg -n 'os\.(system|popen|spawnl?p?e?|exec[lv]p?e?)\(' -g '*.py'
rg -n 'shell\s*=\s*True' -g '*.py'
rg -n 'subprocess\.getoutput|getstatusoutput' -g '*.py'
```
Sanitizers: `subprocess.run([...])` list form without shell; `shlex.quote` is
weak (argument injection via leading `-` flags remains — insert `--`).

### Code/template injection
```
rg -n '(^|[^\w.])(eval|exec|compile|__import__)\(' -g '*.py'
rg -n 'render_template_string\(|jinja2\.Template\(|Environment\(' -g '*.py'
rg -n 'getattr\([^,)]*,\s*request|importlib\.import_module\(.*(request|params)' -g '*.py'
```
SSTI payload to confirm Jinja2: `{{7*7}}` then
`{{cycler.__init__.__globals__.os.popen('id').read()}}`.

### Deserialization
```
rg -n '(pickle|marshal|dill)\.loads?\(|jsonpickle\.decode\(|shelve\.open\(' -g '*.py'
rg -n 'yaml\.(load|load_all|unsafe_load|full_load)\(' -g '*.py'
rg -n 'Loader\s*=\s*(yaml\.)?(Loader|FullLoader|UnsafeLoader)' -g '*.py'
```
`yaml.load(x)` with no Loader is unsafe on PyYAML <5.1; `SafeLoader`/`safe_load`
is the sanitizer. pickle of anything attacker-touchable = RCE
(`__reduce__` gadget). Also: `torch.load`, `joblib.load`, `numpy.load(allow_pickle=True)`.

### SSRF
```
rg -n 'requests\.(get|post|put|patch|delete|head|request)\(' -g '*.py'
rg -n 'urllib\.request\.(urlopen|Request)\(|httpx\.' -g '*.py'
rg -n 'aiohttp\.ClientSession|session\.(get|post)\(' -g '*.py'
```
Check whether the URL/host/path argument contains a request-derived part.
`urllib.request.urlopen` also honors `file://` — arbitrary read.

### Path traversal
```
rg -n 'open\([^)]*(request\.|params\[|\.filename)' -g '*.py'
rg -n 'os\.path\.join\([^)]*(request\.|params\[|\.filename)' -g '*.py'
rg -n 'send_file\(|send_from_directory\(' -g '*.py'
rg -n '\.extractall\(|\.extract\(|tarfile\.open\(' -g '*.py'
```
Trap: `os.path.join("/base", user)` returns `user` unchanged when `user` is
absolute. Sanitizer: `realpath` + prefix check, or `werkzeug.utils.secure_filename`.
Tar: member names and **linknames** (symlink members) both traverse.

### XXE
```
rg -n 'etree\.(parse|fromstring|XMLParser)|xml\.(sax|dom\.minidom|dom\.pulldom)' -g '*.py'
rg -n 'resolve_entities\s*=\s*True|load_dtd\s*=\s*True|XMLParser\(' -g '*.py'
```
stdlib `xml.etree` ignores external entities since 3.7.1; lxml with
`resolve_entities=True` (or old defaults) is vulnerable. Sanitizer: `defusedxml`
or `etree.XMLParser(resolve_entities=False, no_network=True)`.

### Authz / IDOR
```
rg -n '@app\.route\(|@router\.(get|post|put|delete)|path\(|re_path\(' -g '*.py'   # route inventory
rg -n '(objects\.(get|filter)|query\.(get|filter_by)|get_object_or_404)\([^)]*request\.' -g '*.py'
rg -n '@login_required|@permission_required|IsAuthenticated|has_perm' -g '*.py'   # control inventory
```
Diff route inventory vs control inventory; for each fetch-by-request-id,
check for an owner filter (`owner=request.user`, tenant id in query).

### Crypto misuse
```
rg -n 'hashlib\.(md5|sha1)\(' -g '*.py'
rg -n 'MODE_ECB|\bDES3?\b|AES\.new\([^)]*,\s*AES\.MODE_ECB' -g '*.py'
rg -n 'random\.(random|randint|randrange|choice|choices|getrandbits|sample)\(' -g '*.py'
rg -n 'verify\s*=\s*False|_create_unverified_context|check_hostname\s*=\s*False' -g '*.py'
rg -n 'iv\s*=\s*b?["\x27]|key\s*=\s*b?["\x27]' -g '*.py'   # static IV/key literals
```
Password hashing wants `bcrypt`/`scrypt`/`argon2`; tokens want `secrets` module.

### Secrets
```
rg -n -i '(api[_-]?key|secret|passw(or)?d|token|private[_-]?key)\s*=\s*["\x27][A-Za-z0-9+/=_\-]{8,}' -g '*.py' -g '*.cfg' -g '*.ini' -g '*.env*' -g '*.yml' -g '*.yaml'
rg -n 'BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY'
rg -n 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-|sk_live_'
```
For breadth and history scanning, load the `gitleaks` / `trufflehog` skills.

## Common Python sanitizers (recognize, then verify)

| Sanitizer | Neutralizes | Caveats |
|---|---|---|
| `int(x)`, `float(x)`, `uuid.UUID(x)` | nearly all injection | throws on bad input — check it's not swallowed and raw value reused |
| parameterized `execute(q, params)` | SQLi | not identifiers / ORDER BY |
| `subprocess.run([...])` no shell | cmdi | argument injection — use `--` |
| `shlex.quote` | shell metachars only | not flags, not non-shell sinks |
| `markupsafe.escape` | XSS only | nothing else |
| `werkzeug.utils.secure_filename` | traversal in filenames | ASCII-flattens; not full paths |
| `yaml.safe_load` | deser | fine |
| `os.path.realpath` + prefix check | traversal | prefix must end with `os.sep` |
| `defusedxml` | XXE | fine |
