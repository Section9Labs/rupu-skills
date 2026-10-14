# JavaScript / TypeScript / Node: sources, sinks, sanitizers, ripgrep patterns

Scan globs: `-g '*.js' -g '*.jsx' -g '*.ts' -g '*.tsx' -g '*.mjs' -g '*.cjs'`
(abbreviated to `-g '*.js' -g '*.ts'` below).

## Sources

| Context | Expressions |
|---|---|
| Express | `req.query`, `req.body`, `req.params`, `req.headers`, `req.cookies`, `req.files` / multer uploads, `req.hostname` (Host header!) |
| Koa/Fastify/Nest | `ctx.query/ctx.request.body`, `request.query/body/params`, `@Query()/@Body()/@Param()` decorators |
| Generic Node | `process.argv`, `process.env` (when attacker-settable), socket/stream reads, queue consumers, DB reads of user data |
| Browser (DOM XSS sources) | `location.*`, `document.URL`, `document.referrer`, `window.name`, `postMessage` data, `localStorage` of synced data |

## Sinks by class

### SQL / NoSQL injection
```
rg -n '\.query\(\s*(`|["\x27][^"\x27]*["\x27]\s*\+)' -g '*.js' -g '*.ts'
rg -n 'sequelize\.query\(|knex\.raw\(|\$queryRawUnsafe|\$executeRawUnsafe' -g '*.js' -g '*.ts'
rg -n '\$where|mapReduce\(|db\.eval\(' -g '*.js' -g '*.ts'          # Mongo JS injection
rg -n 'find(One)?\(\s*req\.(query|body)' -g '*.js' -g '*.ts'        # Mongo operator injection ({"$gt":""})
```
Sanitizers: placeholders (`?` / `$1` / named bind), Prisma `$queryRaw` tagged
template (safe) vs `$queryRawUnsafe` (not), `mongo-sanitize`/schema casting for
operator injection.

### Command injection
```
rg -n "require\(['\x22]child_process|from ['\x22]child_process" -g '*.js' -g '*.ts'
rg -n '(^|[^\w.])exec(Sync)?\(' -g '*.js' -g '*.ts'
rg -n 'spawn(Sync)?\([^)]*shell\s*:\s*true|execFile' -g '*.js' -g '*.ts'
```
`exec()` always goes through a shell; `execFile`/`spawn` (array args, no
`shell:true`) are the sanitizer. Watch wrapper libs: `shelljs.exec`, `execa`
with `shell: true`.

### Code injection / SSTI / prototype pollution
```
rg -n '(^|[^\w.])eval\(|new Function\(' -g '*.js' -g '*.ts'
rg -n 'vm\.(runInNewContext|runInThisContext|compileFunction)\(|vm2' -g '*.js' -g '*.ts'
rg -n 'set(Timeout|Interval)\(\s*["\x27`]' -g '*.js' -g '*.ts'
rg -n 'handlebars\.compile\(|ejs\.render\(|pug\.render\(|nunjucks\.renderString\(' -g '*.js' -g '*.ts'
rg -n 'res\.render\(\s*(req\.|[^,)]*\+)' -g '*.js' -g '*.ts'        # user-chosen template name
rg -n '(merge|extend|defaultsDeep|setWith|set)\(\s*[^,)]*,\s*req\.' -g '*.js' -g '*.ts'  # proto pollution candidates
```
SSTI confirm: ejs `<%= 7*7 %>` via injected template; nunjucks
`{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}`.
Prototype pollution: user JSON into deep-merge → check `__proto__`/`constructor.prototype` key handling.

### Deserialization
```
rg -n "require\(['\x22]node-serialize|serialize-to-js" -g '*.js' -g '*.ts'
rg -n '(^|[^\w.])unserialize\(' -g '*.js' -g '*.ts'
rg -n 'yaml\.load\(' -g '*.js' -g '*.ts'    # js-yaml <4 or explicit unsafe types
```
node-serialize `unserialize()` executes `_$$ND_FUNC$$_` IIFE payloads → RCE.
js-yaml v4 `load` is safe-by-default; v3 needs `safeLoad`.

### SSRF
```
rg -n 'axios(\.(get|post|put|delete|request))?\(' -g '*.js' -g '*.ts'
rg -n '(^|[^\w.])fetch\(|got(\.\w+)?\(|node-fetch' -g '*.js' -g '*.ts'
rg -n 'https?\.(get|request)\(' -g '*.js' -g '*.ts'
```
Check for request-derived URL/host. Node `http.get` accepts `unix:` sockets
via agent options; axios follows redirects by default.

### Path traversal
```
rg -n 'fs\.(readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rm|rmdir|readdir|stat)(Sync)?\(' -g '*.js' -g '*.ts'
rg -n 'res\.(sendFile|download)\(|express\.static\(' -g '*.js' -g '*.ts'
rg -n 'path\.join\([^)]*req\.|path\.resolve\([^)]*req\.' -g '*.js' -g '*.ts'
```
Trap: `path.join(base, "../../etc/passwd")` escapes; `path.resolve(base, user)`
with absolute `user` discards base. Sanitizer: `path.resolve` then
`resolved.startsWith(base + path.sep)`; `res.sendFile(name, {root: base})`
does its own containment check.
Zip-slip: `yauzl`/`adm-zip` entry names joined into extract dir.

### XXE
```
rg -n 'libxmljs|noent\s*:\s*true' -g '*.js' -g '*.ts'
```
`xml2js`/`fast-xml-parser` don't expand external entities; `libxmljs` with
`{noent: true}` does.

### Authz / IDOR
```
rg -n '(router|app)\.(get|post|put|patch|delete)\(' -g '*.js' -g '*.ts'      # route inventory
rg -n '(findById|findOne|findByPk)\([^)]*req\.(params|query|body)' -g '*.js' -g '*.ts'
rg -n 'requireAuth|isAuthenticated|passport\.authenticate|authorize\(' -g '*.js' -g '*.ts'
```
Match each fetch-by-request-id with an ownership predicate
(`{ _id: id, owner: req.user.id }`) or a policy middleware on the route.

### Crypto misuse
```
rg -n 'createHash\(\s*["\x27](md5|sha1)' -g '*.js' -g '*.ts'
rg -n 'createCipher\(' -g '*.js' -g '*.ts'                 # deprecated, EVP key-derive, no IV
rg -n 'Math\.random\(' -g '*.js' -g '*.ts'                 # judge the use: token vs cosmetic
rg -n 'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED' -g '*.js' -g '*.ts'
```
Tokens want `crypto.randomBytes`/`randomUUID`; passwords want bcrypt/argon2.

### Secrets
```
rg -n -i '(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*["\x27][A-Za-z0-9+/=_\-]{8,}' -g '*.js' -g '*.ts' -g '*.json' -g '*.env*'
```
Load `gitleaks` / `trufflehog` skills for history + entropy coverage.

## Common JS sanitizers

| Sanitizer | Neutralizes | Caveats |
|---|---|---|
| `parseInt(x, 10)` / `Number(x)` | injections when result used | `NaN` fallthrough — check it's handled |
| placeholders / tagged `$queryRaw` | SQLi | not identifiers |
| `execFile`/`spawn` array args | cmdi | not with `shell:true`; `--` for flags |
| `path.resolve` + `startsWith(base+sep)` | traversal | must append separator |
| template auto-escaping (`<%= %>` ejs, `{{ }}` nunjucks) | XSS | raw forms `<%- %>`, `| safe` bypass |
| `JSON.parse` | — | parse is safe; what you do with the object isn't |
