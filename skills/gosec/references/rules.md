# gosec rule catalog (Gxxx) by vulnerability class

Severity/confidence shown are gosec defaults; CWE as mapped by gosec.

## Injection

### G201 — SQL built with format string (CWE-89)
```go
q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.Query(q)
```
Flags `fmt.Sprintf`/`Sprintln` results flowing into `database/sql`
Query/QueryRow/Exec (and Context variants). Verify: is the formatted value
user input? Parameterized `db.Query("... WHERE name = ?", name)` is the fix.
Does **not** see ORM raw methods (`gorm.Raw`, sqlx) — hand those to
semgrep/codeql.

### G202 — SQL built with string concatenation (CWE-89)
```go
rows, err := db.Query("SELECT * FROM items WHERE owner = '" + owner + "'")
```
Only triggers when a non-constant operand is concatenated into the query at
the call site. Concatenation done in a helper function escapes detection.

### G204 — Subprocess launched with variable (CWE-78)
```go
out, err := exec.Command("sh", "-c", userCmd).Output()
cmd := exec.Command(binPath, args...)       // variable program path also flagged
```
Covers `os/exec.Command`, `CommandContext`, `syscall.Exec/ForkExec/StartProcess`.
Triage: variable **argv element** with a fixed program is usually safe-ish
(no shell) unless the program interprets options/subcommands or `-c` is
present; variable program path or anything through `sh -c`/`cmd /C` is the
real target.

### G107 — URL from variable passed to HTTP request (CWE-88, SSRF)
```go
resp, err := http.Get(target) // target from request parameter -> SSRF
```
Covers `http.Get/Post/Head/PostForm` and `http.NewRequest` with non-constant
URL. Check for internal-network reachability, metadata endpoints
(169.254.169.254), file:// via custom transports.

### G203 — Unescaped data in HTML template (CWE-79)
```go
tmpl.Execute(w, template.HTML(userInput))   // bypasses html/template autoescape
```
Flags conversions to `template.HTML`, `template.JS`, `template.URL`,
`template.HTMLAttr`, `template.CSS` from non-constant data. Also review any
use of `text/template` to render HTML — gosec will not flag that; grep for it.

## Filesystem

### G304 — File path from tainted input (CWE-22)
```go
f, err := os.Open(filepath.Join(baseDir, req.URL.Query().Get("file")))
data, err := os.ReadFile(userPath)
```
Covers `os.Open/OpenFile/Create/ReadFile`, `ioutil.ReadFile`. `filepath.Clean`
alone does NOT prevent traversal (clean of `../../etc/passwd` is still
traversal); containment requires checking the resolved path has the base as
prefix after `filepath.Abs`/`EvalSymlinks`. Verify reachability from input.

### G305 — Zip/tar slip during archive extraction (CWE-22)
```go
for _, f := range zr.File {
    path := filepath.Join(dest, f.Name)   // f.Name may contain ../
    os.Create(path)
}
```

### G110 — Decompression bomb (CWE-409)
```go
io.Copy(dst, gzipReader)   // unbounded; use io.CopyN / io.LimitReader
```

### G301–G307 — Permissions and temp files
- **G301** `os.Mkdir/MkdirAll` with mode > 0750 (CWE-276)
- **G302** `os.Chmod/OpenFile` with mode > 0600 on sensitive files
- **G303** predictable path in `/tmp` (`ioutil.WriteFile("/tmp/x", ...)`) (CWE-377)
- **G304** (above)
- **G305** (above)
- **G306** `ioutil.WriteFile`/`os.WriteFile` perms > 0600
- **G307** poor `defer` of `.Close()` on writable file (error dropped; data loss / partial write) — removed in some newer versions
Triage G301/G302/G306 by what the file holds: keys, tokens, DB files matter;
cache files rarely do.

### G111 — Directory traversal via `http.Dir("/")` / overly broad FileServer root (CWE-22)

## Crypto

### G401 — Weak crypto primitive use (CWE-328/326)
```go
h := md5.Sum(data)      // also sha1.Sum; newer versions split G401(MD5/SHA1 hash) / G405(DES/RC4 cipher) / G406(MD4/RIPEMD)
```
Context decides severity: MD5 for a cache key is noise; MD5 over passwords or
signatures is a finding.

### G402 — Bad TLS settings (CWE-295)
```go
&tls.Config{InsecureSkipVerify: true}
&tls.Config{MinVersion: tls.VersionSSL30}        // or VersionTLS10/11
&tls.Config{CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}}
```
`InsecureSkipVerify: true` in non-test code is almost always a real MITM
finding; check whether a custom `VerifyPeerCertificate` compensates.

### G403 — Weak RSA key length (< 2048) (CWE-326)
```go
key, _ := rsa.GenerateKey(rand.Reader, 1024)
```

### G404 — Insecure random source (CWE-338)
```go
token := fmt.Sprintf("%d", rand.Int63())   // math/rand — predictable, seedable
```
Finding when output is a session token, password-reset token, API key, nonce,
or filename meant to be unguessable. `crypto/rand` is the fix. Noise when used
for jitter/backoff/sampling.

### G501–G505 — Blocklisted crypto imports (CWE-327)
- G501 `crypto/md5` · G502 `crypto/des` · G503 `crypto/rc4` ·
  G504 `net/http/cgi` (Httpoxy) · G505 `crypto/sha1`
- G506 `golang.org/x/crypto/md4` · G507 `golang.org/x/crypto/ripemd160`
Import-level: fires even if unused for anything sensitive — correlate with
G401 call sites.

## Credentials & secrets

### G101 — Hardcoded credentials (CWE-798)
```go
const apiToken = "ghp_exampleexampleexampleexample0000"
password := "s3cretP@ss"
```
Matches variable/const names against a regex (passwd|password|secret|token|
apikey|...) plus an entropy check; both are configurable via `-conf`. False
positives: `const TokenHeader = "X-Auth-Token"` (name of a header, not a
secret). Follow up with a dedicated secret scanner (gitleaks/trufflehog) and
git history review — gosec only sees current source.

## Memory / language safety

### G103 — Use of `unsafe` (CWE-242)
```go
p := unsafe.Pointer(&s)
b := *(*[]byte)(p)
```
Audit each use for out-of-bounds reinterpretation, lifetime bugs, string/byte
aliasing that breaks immutability.

### G115 — Integer overflow in conversion (CWE-190)
```go
n := len(data)           // int (64-bit)
hdr.Length = uint16(n)   // silently truncates > 65535
size := int32(userLen)   // negative wrap if userLen > MaxInt32
```
High-value when the truncated value feeds an allocation, bounds check, or
length header. Check whether a range guard precedes the conversion.

### G601 — Implicit memory aliasing of loop variable (`&v` inside `range`) — pre-Go-1.22 bug class
### G602 — Slice access out of bounds (constant-detectable)

## Errors & availability

### G104 — Unhandled errors (CWE-703)
```go
f.Write(data)        // error dropped
_ = conn.Close()
```
Massive volume. Security-relevant subset: dropped errors from crypto
verification, `io.ReadFull(rand.Reader, ...)`, auth checks, `Write` of
security state. Configure ignore lists via `-conf` G104 or `-exclude G104`
on sweeps and review the subset manually.

### G105 — math/big `Exp` audit (historic CVE) · G106 — `ssh.InsecureIgnoreHostKey` (CWE-322)
### G108 — `net/http/pprof` imported (profiling endpoint exposed on default mux) (CWE-200)
### G109 — `strconv.Atoi` result converted to narrower int (overflow; folded into G115 in newer versions)
### G112 — `http.Server` without `ReadHeaderTimeout` (Slowloris, CWE-400)
### G113 — `math/big.Rat.SetString` crafted-input CVE (old Go versions)
### G114 — `http.ListenAndServe` directly (no timeouts configurable) (CWE-676)

## Network

### G102 — Binding to all interfaces (CWE-200)
```go
l, _ := net.Listen("tcp", "0.0.0.0:9000")
http.ListenAndServe(":8080", nil)   // empty host = all interfaces
```
Finding when the service is meant to be localhost-only (debug/admin/metrics
endpoints); normal for a public server behind proper network policy.

## Version note

Rule ids shift between gosec releases: newer versions split G401 into
G401/G405/G406/G407 (hash vs cipher vs nonce reuse) and retire G307. Always
read ids from the actual output JSON (`rule_id`) rather than assuming — the
work-unit script carries whatever id the installed version emits.
