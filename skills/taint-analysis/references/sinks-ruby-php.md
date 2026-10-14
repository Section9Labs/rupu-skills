# Ruby & PHP: sources, sinks, sanitizers, ripgrep patterns

## Ruby (Rails) — scan `-g '*.rb' -g '*.erb'`

### Sources
`params` (everything), `request.headers`, `request.body`, `cookies`,
`request.host`, uploaded file `original_filename`, URL/route segments,
`ENV` in attacker-settable layers, DB reads of user data (second-order),
`Marshal`/`YAML`-decoded session or cache data.

### SQL injection
```
rg -n '\.(where|order|group|having|select|from|joins)\(\s*"[^"]*#\{' -g '*.rb'
rg -n 'find_by_sql\(|connection\.(execute|select_all|exec_query)\(' -g '*.rb'
rg -n '\.(order|pluck|group)\(\s*params' -g '*.rb'      # identifier injection
```
Vuln: `User.where("name = '#{params[:name]}'")`
Fix: `User.where(name: params[:name])` or `where("name = ?", params[:name])`.
`order(params[:sort])` is injectable even though `where` hash form is safe —
identifiers need an allowlist.

### Command injection
```
rg -n '(^|[^\w.])(system|exec|spawn)\(' -g '*.rb'
rg -n '%x[\[({]|`[^`]*#\{' -g '*.rb'
rg -n 'Open3\.(capture2e?|capture3|popen2e?|popen3)\(' -g '*.rb'
rg -n 'IO\.popen\(|open\(\s*"\||open\(\s*params' -g '*.rb'
```
Trap: `Kernel#open("| cmd")` executes a command — `open(params[:f])` is both
traversal AND cmdi (payload `|id`). Sanitizer: multi-arg form
`system("ping", "--", host)` bypasses the shell.

### Code injection / SSTI
```
rg -n '(^|[^\w.])eval\(|instance_eval|class_eval|module_eval' -g '*.rb'
rg -n '\.send\(\s*params|public_send\(\s*params|\.constantize|safe_constantize' -g '*.rb'
rg -n 'ERB\.new\(|render\s+inline:|render\(\s*inline:' -g '*.rb'
```
Vuln: `render inline: "Hello #{params[:name]}"` → payload
`<%= `id` %>` via name = full RCE.
Fix: `render plain:` or pass via locals into a file template.
`params[:m].constantize` / `send(params[:a])` → arbitrary method dispatch.

### Deserialization
```
rg -n 'Marshal\.load\(|Marshal\.restore\(' -g '*.rb'
rg -n 'YAML\.load\(|YAML\.load_file\(|Psych\.load\(' -g '*.rb'
rg -n 'Oj\.(load|object_load)\(' -g '*.rb'
```
`Marshal.load` on attacker bytes = gadget RCE (universal gadget chains exist).
`YAML.load` is safe-by-default on Psych 4+ (Ruby 3.1+); earlier needs
`YAML.safe_load`. `Oj.load` in `:object` mode instantiates arbitrary classes.

### SSRF / path traversal / XXE
```
rg -n 'Net::HTTP\.(get|get_response|post|start)\(|URI\.open\(|RestClient\.|Faraday\.' -g '*.rb'
rg -n 'File\.(read|open|write|delete|binread)\([^)]*(params|#\{)' -g '*.rb'
rg -n 'send_file\(|send_data\(' -g '*.rb'
rg -n 'Nokogiri::XML\([^)]*NOENT|\.noent|Nokogiri::XML\(' -g '*.rb'
```
Nokogiri is safe by default; `Nokogiri::XML(x) { |c| c.noent }` or
`ParseOptions::NOENT` enables XXE. `send_file params[:path]` = arbitrary read.

### Authz / IDOR
```
rg -n '\.find(_by)?\(\s*params\[:?\w*id' -g '*.rb'
rg -n 'before_action\s+:(authenticate|authorize|require)' -g '*.rb'
rg -n 'skip_before_action|load_and_authorize_resource|policy_scope|authorize[ (]' -g '*.rb'
```
Vuln: `Doc.find(params[:id])` → Fix: `current_user.docs.find(params[:id])`.
Audit `skip_before_action` lines and controllers missing Pundit/CanCanCan calls.
Also mass assignment: `rg -n 'permit!|update\(params\[' -g '*.rb'`.

### Crypto / secrets
```
rg -n 'Digest::(MD5|SHA1)|OpenSSL::Cipher[^\n]*(ECB|DES)' -g '*.rb'
rg -n '(^|[^\w.])rand\(|Array\.new\([^)]*rand' -g '*.rb'     # tokens want SecureRandom
rg -n 'VERIFY_NONE|verify_mode\s*=' -g '*.rb'
rg -n -i '(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*["\x27][A-Za-z0-9+/=_\-]{8,}' -g '*.rb' -g '*.yml'
```

---

## PHP — scan `-g '*.php' -g '*.phtml'`

### Sources
`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` (names!), `$_SERVER`
(`HTTP_*` headers, `PHP_SELF`, `REQUEST_URI`, `HTTP_HOST`,
`HTTP_X_FORWARDED_FOR`), `php://input`, `getallheaders()`; Laravel
`$request->input/query/post/header/cookie`; Symfony `$request->query->get()` etc.

### SQL injection
```
rg -n '(mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\$' -g '*.php'
rg -n '->(query|exec)\s*\([^)]*(\$|\.\s*\$)' -g '*.php'
rg -n '(SELECT|INSERT|UPDATE|DELETE)[^;]*["\x27]\s*\.\s*\$' -g '*.php'
rg -n 'DB::(select|statement|raw)\(|whereRaw\(|orderByRaw\(' -g '*.php'
```
Vuln: `$db->query("SELECT * FROM users WHERE id = " . $_GET['id']);`
Fix: `$st = $db->prepare("SELECT * FROM users WHERE id = ?"); $st->execute([$_GET['id']]);`
`addslashes` is NOT a sanitizer (multibyte bypass); `intval()` is.

### Command injection
```
rg -n '(^|[^\w$])(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(' -g '*.php'
rg -n '`[^`]*\$' -g '*.php'
```
Sanitizers: `escapeshellarg()` per argument (not `escapeshellcmd` on the whole
string — it permits argument injection), or avoid the shell entirely.

### Code injection / LFI-RFI
```
rg -n '(^|[^\w$])eval\s*\(|(^|[^\w$])assert\s*\(\s*\$|create_function\s*\(' -g '*.php'
rg -n 'preg_replace\s*\([^,)]*/[a-z]*e[a-z]*["\x27]' -g '*.php'      # /e modifier (PHP<7)
rg -n 'call_user_func(_array)?\s*\(\s*\$|\$\w+\s*\(\s*\$' -g '*.php' # variable functions
rg -n '(include|include_once|require|require_once)\s*\(?\s*(\$|["\x27][^"\x27]*["\x27]\s*\.\s*\$)' -g '*.php'
```
`include $_GET['page'];` = LFI → RCE via `php://filter`, wrappers, log
poisoning, or (with `allow_url_include`) RFI. Sanitizer: allowlist map of
page-name → file; never concatenate.
Twig SSTI: `rg -n 'createTemplate\(|render\(\s*\$' -g '*.php'` — payload
`{{_self.env.registerUndefinedFilterCallback("exec")}}` family (version-dependent).

### Deserialization
```
rg -n '(^|[^\w$])unserialize\s*\(\s*\$' -g '*.php'
rg -n 'function\s+__(wakeup|destruct|toString)\(' -g '*.php'   # gadget inventory
rg -n 'phar://' -g '*.php'
```
`unserialize($user)` + any gadget (`__destruct`/`__wakeup` chains, e.g. via
bundled libs) = object injection → often RCE. Also `phar://` metadata
deserialization fires on mere `file_exists()`/`getimagesize()` of a
user-controlled path. Sanitizer:
`unserialize($x, ['allowed_classes' => false])` or JSON.

### SSRF / path traversal / XXE
```
rg -n 'file_get_contents\s*\(\s*\$|fopen\s*\(\s*\$|readfile\s*\(\s*\$' -g '*.php'
rg -n 'curl_init\s*\(\s*\$|CURLOPT_URL\s*,\s*\$|fsockopen\s*\(\s*\$' -g '*.php'
rg -n '(file_put_contents|unlink|copy|rename|move_uploaded_file)\s*\(\s*\$' -g '*.php'
rg -n 'simplexml_load_(string|file)\s*\(|->loadXML\s*\(|LIBXML_NOENT|libxml_disable_entity_loader' -g '*.php'
```
`file_get_contents($url)` honors `http://`, `file://`, `php://`, `data://` —
simultaneously SSRF and arbitrary read. libxml2 ≥2.9 disables entity
substitution unless `LIBXML_NOENT` is passed — any `LIBXML_NOENT` on user XML
is a finding. Traversal sanitizer: `realpath()` + prefix check, `basename()`
for filenames.

### Authz / IDOR
```
rg -n '(find|findOrFail|where)\s*\(\s*\$(request|_GET|_POST|_REQUEST)' -g '*.php'
rg -n '\$this->authorize\(|Gate::|->can\(|middleware\(' -g '*.php'
```
Laravel: fetch-by-id without `authorize()`/policy or `->where('user_id',
auth()->id())` scoping = IDOR candidate. Plain PHP: look for `$_SESSION`
role checks on admin scripts — files reachable directly under webroot skip
the router's checks entirely.

### Crypto / secrets
```
rg -n '(^|[^\w$])(md5|sha1)\s*\(\s*\$' -g '*.php'          # want password_hash()
rg -n '(^|[^\w$])(mt_rand|rand|uniqid)\s*\(' -g '*.php'    # want random_bytes()
rg -n 'mcrypt_|MCRYPT_|openssl_encrypt\([^)]*ecb' -g '*.php'
rg -n 'CURLOPT_SSL_VERIFYPEER\s*(,|=>)\s*(false|0)|CURLOPT_SSL_VERIFYHOST\s*(,|=>)\s*(false|0)' -g '*.php'
rg -n -i '(api[_-]?key|secret|passw(or)?d|token)\s*=>?\s*["\x27][A-Za-z0-9+/=_\-]{8,}' -g '*.php' -g '*.env*' -g '*.ini'
```
Also `rg -n 'strcmp\([^)]*\$_(GET|POST)' -g '*.php'` — loose comparison /
type-juggling auth bypass (`strcmp($pw, $_POST['p']) == 0` with array input).

### Common sanitizers (both languages)

| Sanitizer | Neutralizes | Caveats |
|---|---|---|
| `Integer()` / `intval()` / `(int)` cast | injections | `intval("5 OR 1=1")` = 5 — good |
| prepared statements / `?` binds | SQLi | not identifiers |
| multi-arg `system()` / `escapeshellarg` | cmdi | `escapeshellcmd` alone is bypassable |
| `realpath` + prefix / `basename` | traversal | prefix needs trailing `/` |
| `YAML.safe_load` / `allowed_classes=>false` | deser | — |
| `ERB::Util.html_escape` / `htmlspecialchars($x, ENT_QUOTES)` | XSS | per-context |
