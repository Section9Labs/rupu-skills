# Brakeman Warning-Type Catalog

Grouped by vulnerability class. For each: what Brakeman flags, a vulnerable
Rails snippet, how to confirm exploitability, and typical CWE. Check names
(for `-t`/`-x`) in parentheses.

## Injection

### SQL Injection (`SQL`) - CWE-89
Flags string interpolation/concatenation in `where`, `find_by_sql`, `order`,
`group`, `having`, `joins`, `pluck`, `select`, `exists?`, `delete_all`,
`update_all`, `calculate`, raw `connection.execute`.

```ruby
User.where("name = '#{params[:name]}'")          # High if params direct
User.order(params[:sort])                        # order() takes raw SQL
Project.find_by_sql("... #{current_user.company.name} ...")  # Medium
```

Confirm: build `' OR '1'='1` / `1);SELECT pg_sleep(5)--` style input;
note that `order`/`group`/`pluck` injections need SQL-fragment payloads, not
quoted-string breakouts (`params[:sort] = "(CASE WHEN ... )"`). Safe forms:
hash conditions, `where("name = ?", x)`, `sanitize_sql_like`.

### Command Injection (`Execute`) - CWE-78
Backticks, `%x{}`, `system`, `exec`, `Open3.*`, `IO.popen`, `spawn` with
interpolated input; also `system("sh", "-c", tainted)`.

```ruby
system("convert #{params[:file]} out.png")
`ping -c1 #{params[:host]}`
```

Confirm: `;id`, `$(id)`, backtick payloads. Multi-arg `system("cmd", arg)` is
safe from shell injection (argument injection may remain - check for `--`
handling, e.g. `curl` / `git` argument options).

### Dangerous Send (`Send`) - CWE-470
`obj.send(params[:method])` / `public_send` / `try` with user-controlled
method name or receiver.

```ruby
User.send(params[:action], params[:arg])
```

Confirm: which methods become reachable (`destroy_all`, `instance_eval`,
`system` on Kernel). `public_send` limits to public methods, still often fatal.

### Unsafe Reflection / Remote Code Execution (`UnsafeReflection`, `UnsafeReflectionMethods`, `EvalWarning` reported as `Remote Code Execution` / `Dangerous Eval`) - CWE-94/CWE-470
`constantize`, `safe_constantize`, `const_get`, `classify.constantize`,
`Object.const_get(params[...])`, `method(params[...])`, and any `eval`,
`instance_eval`, `class_eval` with tainted strings.

```ruby
klass = params[:type].classify.constantize
klass.new(user_params)
eval("#{params[:expr]}")                 # Dangerous Eval, always High
```

Confirm: enumerate instantiable classes; chained with mass assignment or
`new` this is frequently full RCE. `eval` of user input = immediate RCE.

### Unsafe Deserialization (`Deserialize`, `UnsafeDeserialize`) - CWE-502
`Marshal.load`/`restore`, `YAML.load` (pre-psych4 unsafe default),
`YAML.unsafe_load`, `CSV.load`, `Oj.load` without safe mode on tainted data.

```ruby
data = Marshal.load(Base64.decode64(cookies[:prefs]))
cfg  = YAML.load(params[:config])
```

Confirm: Marshal/YAML gadget chains against the app's gem set
(universal-deserialisation gadgets for Ruby 3.x are public). Also flags
`ActiveRecord` YAML column serialization on vulnerable Rails
(CVE-2022-32224).

## Cross-Site Scripting - CWE-79

Brakeman reports many XSS variants; all surface as `Cross-Site Scripting`
with different check names:

- (`CrossSiteScripting`) - `<%= raw x %>`, `html_safe`, unescaped params or
  model attributes in ERB/HAML/Slim: `<%= params[:q] %>` is auto-escaped on
  Rails 3+, but `<%= raw params[:q] %>` / `<%== x %>` are flagged.
- (`ContentTag`) - `content_tag(:div, body, attrs)`: attribute *names* and
  (pre-Rails 5.x fixes) some values are not escaped:
  `content_tag(:a, "x", href: params[:url])` → `javascript:` URI.
- (`LinkTo`, `LinkToHref`) - `link_to(body, params[:url])`: href accepts
  `javascript:`/`data:` schemes; body unescaped on Rails 2.
- (`JSONEncoding`, `JSONEntityEscape`) - `<%= raw user.to_json %>` or
  `json_escape` disabled; `</script>` breakout inside a script block.
- (`SanitizeMethods` / `SanitizeConfigCve`) - vulnerable `rails-html-sanitizer`
  / `sanitize` configs (CVE-2022-32209 etc.): allowed `select`/`style` tags →
  bypass.
- (`SimpleFormat`) - `simple_format(tainted)` older CVEs.
- (`Mail To` / `CheckMailTo`) - `mail_to` with `encode: :javascript` on
  vulnerable Rails.
- (`XssFlashInjection` style flags via `CrossSiteScripting`) - `flash[:notice]
  = params[...]` later rendered raw.

Confirm: identify the render context (HTML body, attribute, script block, URI
attribute) and craft the matching payload (`<svg onload=alert(1)>`,
`" autofocus onfocus=alert(1) x="`, `javascript:alert(1)`,
`</script><script>alert(1)</script>`). The `render_path` field in JSON output
tells you which actions reach the template.

## File / Path

### File Access (`FileAccess`, `FileDisclosure`) - CWE-22/CWE-73
`File.read/open/write`, `IO.read`, `Dir[...]`, `send_file`, `FileUtils.*`
with tainted paths.

```ruby
send_file Rails.root.join("files", params[:name])   # ../../ traversal
File.read("uploads/#{params[:f]}")
```

Confirm: `../../../etc/passwd`, absolute-path override via `File.join` /
`Pathname#join` (an absolute second arg replaces the base). `Kernel#open` with
a `|cmd` prefix is command execution, not just file read.

### Dynamic Render Path (`Render`, `RenderDoS`, `RenderInline`) - CWE-22/CWE-94
`render params[:page]`, `render template: tainted`, `render inline: tainted`.

```ruby
render params[:template]          # LFI: any file in app readable as template
render inline: params[:snippet]   # direct ERB injection = RCE
```

Confirm: `render file:`/bare render with traversal reads arbitrary files and,
if an attacker can plant ERB (log poisoning, uploads), executes it. On Rails
< 5.0 / specific versions this is CVE-2016-0752-class RCE. `render inline:`
with user input is always RCE.

## Request Forgery / Redirects

### Redirect (`Redirect`) - CWE-601
`redirect_to params[:url]`, `redirect_to request.referer`, model-sourced URLs.

```ruby
redirect_to params[:return_to]
```

Confirm: `//evil.example.net`, `https:/\example.net`, `.@` tricks; Rails 7+
`redirect_to ... allow_other_host:` matters. Pivot value: OAuth token theft,
phishing.

### Server-Side Request Forgery (`SSRF`) - CWE-918
`Net::HTTP.get(params[:url])`, `open-uri` `URI.open`, `Faraday`, `HTTParty`,
`RestClient` with tainted URLs.

```ruby
Net::HTTP.get(URI(params[:webhook]))
```

Confirm: internal targets `http://192.0.2.10/`, link-local metadata endpoints,
`file://` via open-uri, redirect-following to internal hosts, DNS rebinding.

## Mass Assignment & Model

### Mass Assignment (`ModelAttributes`, `MassAssignment`, `PermitAttributes`) - CWE-915
`params.permit!`, `Model.new(params[:user])` without strong parameters,
`attr_accessible` gaps (Rails 3), permitting dangerous attrs
(`permit(:admin, :role_id)` - flagged by `PermitAttributes`).

```ruby
User.new(params[:user])              # no strong params
params.require(:user).permit!        # permits everything
```

Confirm: POST `user[admin]=1`, `user[role_id]=1`. Check model callbacks and
what columns exist (`db/schema.rb`).

### Attribute Restriction / Protection bypass (`ModelAttrAccessible`, `ProtectedAttributes`)
Informational on older Rails: models with no `attr_accessible`. Treat as
mass-assignment candidates.

## Configuration / Framework

### Default Routes (`DefaultRoutes`) - CWE-284
`match ':controller(/:action(/:id))'` in `routes.rb` - every public method on
every controller becomes routable. Confirm by enumerating controller methods
that were never meant to be actions.

### Cross-Site Request Forgery (`ForgerySetting`, `CSRFTokenForgeryCVE`) - CWE-352
Missing `protect_from_forgery` in `ApplicationController`, `protect_from_forgery
except:/skip_before_action :verify_authenticity_token` on state-changing
actions, non-`:exception` strategy on old Rails, and token-forgery CVEs.
Confirm: replay a state-changing request without the token.

### Session / Secrets (`SessionSettings`, `SecretToken`, `SessionManipulation`, `EOLRails`/`EOLRuby`) - CWE-798/CWE-614
Hardcoded `secret_key_base`/`secret_token` in the repo, `httponly: false`,
session cookie misconfig, EOL framework versions. A committed secret on
cookie-store sessions = forgeable sessions and (via Marshal cookies on old
Rails) RCE - escalate these, don't bucket as "config noise".

### Weak Cryptography (`WeakHash`, `WeakRSAKey`, `Digest`) - CWE-327/CWE-326
`MD5`/`SHA1` over passwords or signatures, small/insecure RSA parameters,
`OpenSSL::Cipher` ECB usage.

```ruby
Digest::MD5.hexdigest(password)
```

Confirm impact: password storage vs. cache key (the latter is usually a
non-issue - say so in the ignore note).

### Denial of Service (`RegexDoS`/`ReDoS`, `DivideByZero`) - CWE-1333
Regex built from user input or catastrophic patterns
(`/(a+)+$/ =~ params[:x]`), plus `Regexp.new(params[...])`. Confirm with a
crafted long input and measure; also note `=~ /\A...\z/` vs `^...$`
multiline-bypass validation issues (`FormatValidation` check).

### HTTP Verb Confusion / Header issues (`VerbConfusion`, `ForceSSL`, `HeaderDoS`)
`request.get?` guards that fall through for HEAD, `config.force_ssl` disabled,
header-parsing DoS CVEs.

### Information Disclosure (`DetailedExceptions`, `I18nXSS`, `MimeTypeDoS`, misc CVE checks)
`consider_all_requests_local = true` in production, vulnerable gem versions
(Brakeman ships many point-CVE checks for Rails itself: `Rails5` /
`Rails6` CVE checks, `SprocketsPathTraversal`, etc.). Cross-check gem CVEs
with a dedicated SCA pass on `Gemfile.lock`.

## Reading priority

1. High-confidence: SQL, Execute, Send, UnsafeReflection, Deserialize,
   Render(inline/dynamic), FileAccess, Eval → verify and exploit first.
2. XSS family → classify by render context, verify top reachable ones.
3. Redirect, SSRF → verify reachability + internal pivot value.
4. Mass assignment → check schema for privilege columns.
5. Config class (CSRF/session/secrets/crypto/routes/ReDoS/mail_to) → verify
   environment applicability (production config?) then report in bulk.
