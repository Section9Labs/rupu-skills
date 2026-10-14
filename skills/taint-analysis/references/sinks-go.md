# Go: sources, sinks, sanitizers, ripgrep patterns

Scan glob: `-g '*.go'`.

## Sources

| Context | Expressions |
|---|---|
| net/http | `r.URL.Query()`, `r.URL.Path`, `r.FormValue`, `r.PostFormValue`, `r.Form`, `r.Header`, `r.Cookie(s)`, `r.Body`, `r.Host`, multipart `FileHeader.Filename` |
| gorilla/mux | `mux.Vars(r)` |
| gin | `c.Param`, `c.Query`, `c.PostForm`, `c.GetHeader`, `c.BindJSON` targets |
| echo | `c.Param`, `c.QueryParam`, `c.FormValue`, `c.Bind` targets |
| Generic | `os.Args`, `os.Getenv` (attacker-settable layers), stdin, queue/gRPC message fields, DB reads of user data |

## Sinks by class

### SQL injection
```
rg -n 'db\.(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext)\([^)]*(\+|Sprintf)' -g '*.go'
rg -n 'fmt\.Sprintf\([^)]*(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)' -g '*.go'
rg -n '\.(Raw|Exec)\([^)]*(\+|Sprintf)' -g '*.go'          # GORM raw
rg -n 'Where\(\s*(fmt\.Sprintf|"[^"]*"\s*\+)' -g '*.go'    # GORM string condition
```
Sanitizer: placeholder args (`$1`/`?`) — `db.Query("... WHERE id = $1", id)`;
GORM `Where("name = ?", name)`. Identifiers (table/column/ORDER BY) still need
an allowlist map.

### Command injection
```
rg -n 'exec\.Command(Context)?\(\s*"(sh|bash|cmd|powershell)"' -g '*.go'
rg -n 'exec\.Command(Context)?\([^)]*\+' -g '*.go'
rg -n 'syscall\.Exec\(' -g '*.go'
```
`exec.Command(name, args...)` does NOT invoke a shell — injection requires
either `sh -c` + concatenated string, a user-controlled binary *name*, or
argument injection (user arg starting with `-`; insert `"--"`).

### Code/template injection
```
rg -n 'text/template' -g '*.go'                              # used for HTML output = no auto-escaping
rg -n 'template\.(HTML|JS|URL|HTMLAttr|CSS|Srcset)\(' -g '*.go'   # html/template escape bypass
rg -n 'template\.(New\([^)]*\)\.)?Parse\([^)]*(\+|r\.|c\.)' -g '*.go'  # template text from user
```
`html/template` auto-escapes; wrapping user data in `template.HTML(user)`
reintroduces XSS. Parsing a user-supplied template string gives data access to
anything in the context (and method calls on it).

### SSRF
```
rg -n 'http\.(Get|Post|PostForm|Head)\(' -g '*.go'
rg -n 'http\.NewRequest(WithContext)?\(' -g '*.go'
rg -n '(client|c|httpClient)\.Do\(' -g '*.go'
rg -n 'url\.Parse\([^)]*(r\.|c\.(Query|Param)|\+)' -g '*.go'
```
Trace the URL string. Default `http.Client` follows 10 redirects — a
"validated" URL can redirect to `http://169.254.169.254/`. Sanitizer:
parse → allowlist host → custom `DialContext` that re-checks the resolved IP
(blocks DNS rebinding), `CheckRedirect` re-validation.

### Path traversal / zip-slip
```
rg -n '(os\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Rename)|ioutil\.(ReadFile|WriteFile))\(' -g '*.go'
rg -n 'filepath\.Join\([^)]*(r\.|c\.(Param|Query)|mux\.Vars|\+)' -g '*.go'
rg -n 'http\.ServeFile\(|http\.FileServer\(|http\.Dir\(' -g '*.go'
rg -n 'zip\.(OpenReader|NewReader)|tar\.NewReader' -g '*.go'
```
Traps: `filepath.Join(base, "../../x")` cleans but still escapes;
`http.ServeFile` rejects `..` in the *request path* but not in a
program-built path. Sanitizer: `filepath.Clean` + `strings.HasPrefix(p,
base+string(os.PathSeparator))` after `filepath.Abs`, or Go 1.24+ `os.Root`.
Zip/tar extraction: validate each entry name the same way (zip-slip).

### XXE
`encoding/xml` does not resolve external entities — stdlib XML is not
XXE-vulnerable. Flag third-party wrappers around libxml2 (cgo) only.

### Authz / IDOR
```
rg -n '(HandleFunc|Handle|GET|POST|PUT|DELETE)\(\s*"' -g '*.go'       # route inventory
rg -n '(First|Find|Take|Last)\([^)]*(mux\.Vars|r\.URL|c\.Param|c\.Query)' -g '*.go'
rg -n 'middleware|RequireAuth|IsAdmin|CurrentUser|GetUserFromContext' -g '*.go'
```
Match fetch-by-request-id against an owner/tenant predicate in the query or a
check between fetch and use. Check middleware chains per router group — a
route registered on the bare router skips the authed group's middleware.

### Crypto misuse
```
rg -n '(md5|sha1)\.(New|Sum)\(' -g '*.go'
rg -n 'des\.NewCipher|NewTripleDESCipher|rc4\.' -g '*.go'
rg -n 'math/rand' -g '*.go'                     # tokens need crypto/rand
rg -n 'InsecureSkipVerify\s*:\s*true' -g '*.go'
rg -n 'NewCBCEncrypter\([^)]*iv|iv\s*:?=\s*\[\]byte\("' -g '*.go'   # static IV
```
Passwords: `golang.org/x/crypto/bcrypt` / argon2. Tokens: `crypto/rand`.
ECB has no stdlib helper — hand-rolled per-block `Encrypt` loops over
`aes.NewCipher` output are the ECB smell:
```
rg -n 'NewCipher\([^)]*\)[^\n]*\n?[^\n]*for' -g '*.go'
```

### Secrets
```
rg -n -i '(apikey|api_key|secret|password|token)\s*(:=|=|:)\s*"[A-Za-z0-9+/=_\-]{8,}"' -g '*.go'
```
Load `gitleaks` / `trufflehog` skills for breadth.

## Common Go sanitizers

| Sanitizer | Neutralizes | Caveats |
|---|---|---|
| `strconv.Atoi/ParseInt/ParseUint` | injections | error must not fall back to raw |
| placeholder query args | SQLi | not identifiers |
| `exec.Command` fixed argv | cmdi | binary name must be constant; `--` for flags |
| `filepath.Abs`+`Clean`+prefix check / `os.Root` | traversal | prefix needs trailing separator |
| `html/template` auto-escape | XSS | `template.HTML()` bypasses |
| `url.Parse` + host allowlist + IP re-check dialer | SSRF | redirects + rebinding |
