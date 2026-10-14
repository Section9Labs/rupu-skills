#!/usr/bin/env python3
"""sink_hunt.py - ripgrep-driven dangerous-sink enumeration for taint analysis.

Runs ripgrep over a source tree with built-in per-language sink-pattern packs
(the same patterns documented in references/sinks-*.md) and emits a CLEAN
top-level JSON array of work units:

  [{"id": "...", "title": "...",
    "targets": ["path:line", ...],
    "hints": {"vuln_class": "...", "sink": "...", "language": "...",
              "snippet": "..."}}, ...]

Hits are grouped per (file, vuln_class, language) so each unit is one
coherent back-tracing task. The output file is directly consumable by a rupu
workflow (`read_file` + `for_each:`) or a lead agent's `dispatch` fan-out.

Falls back to a pure-Python regex scanner when `rg` is not on PATH.

Usage:
  python3 scripts/sink_hunt.py /path/to/repo -o sink_units.json
  python3 scripts/sink_hunt.py . --lang python --vuln-class sql-injection -o - 
  python3 scripts/sink_hunt.py --list
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Sink-pattern packs: language -> {"globs": [...], "rules": [(class, sink, rg-regex)]}
# Regexes stay inside the subset shared by rust-regex (ripgrep) and Python re:
# no lookaround, no backreferences.
# ---------------------------------------------------------------------------
PACKS = {
    "python": {
        "globs": ["*.py"],
        "rules": [
            ("sql-injection", "execute() with f-string query", r"\.execute(many)?\(\s*f[\"']"),
            ("sql-injection", "execute() with concat/%/format query", r"\.execute(many)?\([^,)\n]*(\+|%[\s(]|\.format\()"),
            ("sql-injection", "ORM raw query escape hatch", r"\.(raw|extra)\(|text\(\s*f[\"']|session\.execute\(\s*[f\"']"),
            ("command-injection", "os.system/popen/spawn", r"os\.(system|popen|spawn\w*|exec\w*)\("),
            ("command-injection", "subprocess with shell=True", r"(subprocess|Popen|run|call|check_output|check_call)[^\n]*shell\s*=\s*True"),
            ("code-injection", "eval/exec/__import__", r"(^|[^\w.])(eval|exec|__import__)\("),
            ("code-injection", "template compiled from string (SSTI)", r"render_template_string\(|jinja2\.Template\(|Template\(\s*request"),
            ("deserialization", "pickle/marshal/dill loads", r"(pickle|marshal|dill)\.loads?\(|jsonpickle\.decode\(|shelve\.open\("),
            ("deserialization", "yaml unsafe load", r"yaml\.(load|load_all|unsafe_load|full_load)\("),
            ("ssrf", "requests/urllib/httpx outbound call", r"requests\.(get|post|put|patch|delete|head|request)\(|urllib\.request\.(urlopen|Request)\(|httpx\.(get|post|request|stream)\("),
            ("path-traversal", "file op fed by request data", r"(open|os\.remove|os\.unlink|os\.rename|shutil\.(rmtree|copy\w*|move))\([^)\n]*(request\.|params\[|argv|\.filename)"),
            ("path-traversal", "os.path.join with user segment / send_file", r"os\.path\.join\([^)\n]*(request\.|params\[|\.filename)|send_file\(|send_from_directory\("),
            ("path-traversal", "archive extraction (zip-slip)", r"\.extractall\(|\.extract\(|tarfile\.open\("),
            ("xxe", "XML parser (check entity settings)", r"(lxml\.)?etree\.(parse|fromstring|XMLParser)|xml\.(sax|dom\.minidom|dom\.pulldom)|resolve_entities\s*=\s*True"),
            ("crypto-misuse", "weak hash / ECB / DES", r"hashlib\.(md5|sha1)\(|MODE_ECB|\bDES3?\b"),
            ("crypto-misuse", "non-CSPRNG for secrets", r"random\.(random|randint|randrange|choice|choices|getrandbits|sample)\("),
            ("crypto-misuse", "TLS verification disabled", r"verify\s*=\s*False|_create_unverified_context|check_hostname\s*=\s*False"),
            ("authz-idor", "object fetched by request-supplied id", r"(objects\.(get|filter)|query\.(get|filter_by)|get_object_or_404)\([^)\n]*request\."),
            ("hardcoded-secret", "credential literal", r"(?i)(api[_-]?key|secret|passw(or)?d|token|private[_-]?key)\s*=\s*[\"'][A-Za-z0-9+/=_\-]{8,}[\"']"),
        ],
    },
    "javascript": {
        "globs": ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"],
        "rules": [
            ("sql-injection", "query() with template/concat string", r"\.query\(\s*(`|[\"'][^\"'\n]*[\"']\s*\+)"),
            ("sql-injection", "sequelize.query/knex.raw", r"sequelize\.query\(|\.raw\(\s*(`|[\"'][^\"'\n]*\+)"),
            ("command-injection", "child_process exec", r"child_process|(^|[^\w.])exec(Sync)?\(|execFile(Sync)?\("),
            ("command-injection", "spawn with shell:true", r"shell\s*:\s*true"),
            ("code-injection", "eval/new Function/vm", r"(^|[^\w.])eval\(|new Function\(|vm\.(runInNewContext|runInThisContext|compileFunction)\("),
            ("code-injection", "string timer / template compile (SSTI)", r"set(Timeout|Interval)\(\s*[\"'`]|handlebars\.compile\(|ejs\.render\(|pug\.render\(|res\.render\(\s*(req\.|[^,\n)]*\+)"),
            ("deserialization", "node-serialize / js-yaml load", r"node-serialize|serialize-to-js|(^|[^\w.])unserialize\(|yaml\.load\("),
            ("ssrf", "outbound HTTP client", r"axios\.(get|post|put|delete|request)\(|(^|[^\w.])fetch\(|https?\.(get|request)\(|got(\.\w+)?\("),
            ("path-traversal", "fs API / sendFile / join(req)", r"fs\.(readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rm|readdir)(Sync)?\(|res\.(sendFile|download)\(|path\.join\([^)\n]*req\."),
            ("xxe", "libxml with noent", r"noent\s*:\s*true|libxmljs"),
            ("crypto-misuse", "weak hash / createCipher", r"createHash\(\s*[\"'](md5|sha1)|createCipher\("),
            ("crypto-misuse", "Math.random for tokens", r"Math\.random\("),
            ("crypto-misuse", "TLS verification disabled", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
            ("authz-idor", "DB fetch keyed by req param", r"(findById|findOne|findByPk)\([^)\n]*req\.(params|query|body)"),
            ("hardcoded-secret", "credential literal", r"(?i)(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*[\"'][A-Za-z0-9+/=_\-]{8,}[\"']"),
        ],
    },
    "java": {
        "globs": ["*.java", "*.kt", "*.kts", "*.scala", "*.groovy"],
        "rules": [
            ("sql-injection", "Statement / concat query", r"createStatement\(|(executeQuery|executeUpdate|execute|addBatch)\([^)\n]*\+"),
            ("sql-injection", "prepare/createQuery with concat", r"(prepareStatement|createQuery|createNativeQuery)\([^)\n]*\+|@Query\([^)\n]*\+"),
            ("command-injection", "Runtime.exec / ProcessBuilder", r"Runtime\.getRuntime\(\)\.exec\(|new ProcessBuilder\("),
            ("code-injection", "ScriptEngine / SpEL / Groovy / OGNL", r"ScriptEngine|parseExpression\(|GroovyShell|Eval\.(me|x)\(|Ognl"),
            ("code-injection", "template engine fed user string (SSTI)", r"templateEngine\.process\(|Velocity\.evaluate\(|createTemplate\("),
            ("deserialization", "ObjectInputStream / readObject", r"new ObjectInputStream\(|\.read(Object|Unshared)\(|XMLDecoder|XStream"),
            ("deserialization", "SnakeYAML / jackson default typing", r"new Yaml\(\)|enableDefaultTyping\(|activateDefaultTyping\("),
            ("ssrf", "URL open / RestTemplate / HttpClient", r"new URL\([^)\n]*\)\.open(Connection|Stream)\(|restTemplate\.(getForObject|getForEntity|postForObject|exchange)\(|HttpClient\.|HttpGet\("),
            ("path-traversal", "File/Paths from concat", r"new (File|FileInputStream|FileOutputStream|FileReader|FileWriter)\([^)\n]*\+|Paths\.get\([^)\n]*\+"),
            ("path-traversal", "zip extraction (zip-slip)", r"new ZipInputStream\(|ZipEntry|getNextEntry\("),
            ("xxe", "XML factory (check doctype features)", r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\(|new SAXReader\("),
            ("crypto-misuse", "ECB/DES / weak digest", r"Cipher\.getInstance\(\s*\"(DES|AES\"|AES/ECB|RSA/ECB)|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\""),
            ("crypto-misuse", "java.util.Random / trust-all TLS", r"new Random\(|checkServerTrusted|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier"),
            ("authz-idor", "repository fetch by request id", r"(findById|getById|getOne)\([^)\n]*(request|param|id)\)"),
            ("hardcoded-secret", "credential literal", r"(?i)(api[_-]?key|secret|passw(or)?d|token)\s*=\s*\"[A-Za-z0-9+/=_\-]{8,}\""),
        ],
    },
    "go": {
        "globs": ["*.go"],
        "rules": [
            ("sql-injection", "db.Query/Exec with concat/Sprintf", r"db\.(Query|QueryRow|QueryContext|Exec|ExecContext)\([^)\n]*(\+|Sprintf)"),
            ("sql-injection", "Sprintf-built SQL string", r"fmt\.Sprintf\([^)\n]*(SELECT|INSERT|UPDATE|DELETE|WHERE)"),
            ("command-injection", "exec.Command via shell / concat", r"exec\.Command(Context)?\(\s*\"(sh|bash|cmd|powershell)\"|exec\.Command(Context)?\([^)\n]*\+"),
            ("code-injection", "text/template or template.HTML bypass", r"template\.(HTML|JS|URL|HTMLAttr)\(|text/template"),
            ("ssrf", "outbound HTTP with variable URL", r"http\.(Get|Post|PostForm|Head)\(|http\.NewRequest(WithContext)?\("),
            ("path-traversal", "file op on joined/user path", r"(os\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)|ioutil\.(ReadFile|WriteFile))\(|filepath\.Join\([^)\n]*r\."),
            ("crypto-misuse", "md5/sha1/des", r"(md5|sha1|des)\.(New|Sum|NewCipher)\("),
            ("crypto-misuse", "math/rand for secrets", r"math/rand"),
            ("crypto-misuse", "TLS verification disabled", r"InsecureSkipVerify\s*:\s*true"),
            ("authz-idor", "DB fetch keyed by request var", r"(First|Find|Take)\([^)\n]*(mux\.Vars|r\.URL|c\.Param|c\.Query)"),
            ("hardcoded-secret", "credential literal", r"(?i)(apikey|api_key|secret|password|token)\s*(:|=|:=)\s*\"[A-Za-z0-9+/=_\-]{8,}\""),
        ],
    },
    "ruby": {
        "globs": ["*.rb", "*.erb", "Gemfile"],
        "rules": [
            ("sql-injection", "where/execute with interpolation", r"\.(where|order|group|having|execute|select_all)\(\s*\"[^\"\n]*#\{|find_by_sql\("),
            ("command-injection", "system/exec/backticks/%x", r"(^|[^\w.])(system|exec|spawn)\(|%x[\[({]|Open3\.(capture\w*|popen\w*)|`[^`\n]*#\{"),
            ("code-injection", "eval / send(params) / constantize / inline ERB", r"(^|[^\w.])eval\(|(instance|class|module)_eval|\.send\(\s*params|constantize|ERB\.new\(|render\s+inline:"),
            ("deserialization", "Marshal/YAML/Oj load", r"Marshal\.load\(|YAML\.load\(|Oj\.(load|object_load)\("),
            ("ssrf", "Net::HTTP / open-uri with variable", r"Net::HTTP\.(get|get_response|post|start)\(|URI\.open\(|open\(\s*params"),
            ("path-traversal", "File op / send_file with params", r"File\.(read|open|write|delete|binread)\([^)\n]*(params|#\{)|send_file\("),
            ("xxe", "Nokogiri with NOENT", r"Nokogiri::XML\([^)\n]*NOENT|\.noent"),
            ("crypto-misuse", "weak digest / rand / VERIFY_NONE", r"Digest::(MD5|SHA1)|OpenSSL[^\n]*ECB|(^|[^\w.])rand\(|VERIFY_NONE"),
            ("authz-idor", "find by params id", r"\.find(_by)?\(\s*params\[:?\w*id"),
            ("hardcoded-secret", "credential literal", r"(?i)(api[_-]?key|secret|passw(or)?d|token)\s*[:=]\s*[\"'][A-Za-z0-9+/=_\-]{8,}[\"']"),
        ],
    },
    "php": {
        "globs": ["*.php", "*.phtml", "*.php5"],
        "rules": [
            ("sql-injection", "query with variable/concat", r"(mysql_query|mysqli_query|pg_query)\([^)\n]*\$|->query\([^)\n]*(\$|\.\s*\$)"),
            ("command-injection", "exec family / backticks", r"(^|[^\w$])(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`\n]*\$"),
            ("code-injection", "eval/assert/preg_replace /e/create_function", r"(^|[^\w$])eval\s*\(|(^|[^\w$])assert\s*\(\s*\$|preg_replace\([^)\n]*/e|create_function\("),
            ("code-injection", "dynamic include/require (LFI)", r"(include|include_once|require|require_once)\s*\(?\s*\$"),
            ("deserialization", "unserialize of variable", r"(^|[^\w$])unserialize\s*\(\s*\$"),
            ("ssrf", "file_get_contents/cURL with variable URL", r"file_get_contents\s*\(\s*\$|curl_init\s*\(\s*\$|CURLOPT_URL\s*,\s*\$|fsockopen\s*\(\s*\$"),
            ("path-traversal", "file op on variable path", r"(fopen|readfile|file_put_contents|unlink|file|copy|rename)\s*\(\s*\$|move_uploaded_file\s*\("),
            ("xxe", "simplexml/DOM with NOENT", r"simplexml_load_(string|file)\(|LIBXML_NOENT|->loadXML\("),
            ("crypto-misuse", "md5/sha1/mt_rand/mcrypt", r"(^|[^\w$])(md5|sha1|mt_rand|rand)\s*\(|mcrypt_"),
            ("crypto-misuse", "TLS verification disabled", r"CURLOPT_SSL_VERIFYPEER\s*(,|=>)\s*(false|0)"),
            ("authz-idor", "fetch keyed by request id", r"(find|findOrFail|where)\s*\(\s*\$(request|_GET|_POST|_REQUEST)"),
            ("hardcoded-secret", "credential literal", r"(?i)(api[_-]?key|secret|passw(or)?d|token)\s*=>?\s*[\"'][A-Za-z0-9+/=_\-]{8,}[\"']"),
        ],
    },
}

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
             ".venv", "venv", "__pycache__", ".tox", "target", ".idea"}


def run_rg(root, globs, pattern):
    cmd = ["rg", "--json", "-e", pattern]
    for g in globs:
        cmd += ["-g", g]
    cmd.append(root)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    except OSError as exc:
        print("error running rg: %s" % exc, file=sys.stderr)
        return []
    hits = []
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("type") != "match":
            continue
        d = obj["data"]
        text = d["lines"].get("text", "").rstrip("\n")
        hits.append((d["path"]["text"], d["line_number"], text))
    return hits


def run_python_scan(root, globs, pattern):
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        print("skipping pattern %r (python re incompatible: %s)" % (pattern, exc), file=sys.stderr)
        return []
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not any(fnmatch.fnmatch(fn, g) for g in globs):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if rx.search(line):
                            hits.append((path, i, line.rstrip("\n")))
            except OSError:
                continue
    return hits


def main():
    ap = argparse.ArgumentParser(description="Enumerate dangerous sinks with ripgrep and emit rupu work units.")
    ap.add_argument("root", nargs="?", default=".", help="source tree to scan (default .)")
    ap.add_argument("-o", "--output", default="sink_units.json",
                    help="output file for the JSON work-unit array ('-' for stdout; default sink_units.json)")
    ap.add_argument("--lang", action="append", choices=sorted(PACKS),
                    help="restrict to language pack(s); repeatable (default: all)")
    ap.add_argument("--vuln-class", action="append", dest="vclasses",
                    help="restrict to vulnerability class(es), e.g. sql-injection; repeatable")
    ap.add_argument("--max-targets", type=int, default=40,
                    help="cap targets per work unit (default 40)")
    ap.add_argument("--no-rg", action="store_true", help="force the pure-Python fallback scanner")
    ap.add_argument("--list", action="store_true", help="list languages, classes and patterns, then exit")
    args = ap.parse_args()

    if args.list:
        for lang in sorted(PACKS):
            print("[%s] globs=%s" % (lang, ",".join(PACKS[lang]["globs"])))
            for vclass, sink, pat in PACKS[lang]["rules"]:
                print("  %-20s %-45s %s" % (vclass, sink, pat))
        return 0

    use_rg = (not args.no_rg) and shutil.which("rg") is not None
    if not use_rg:
        print("note: rg not found or --no-rg; using pure-Python scanner (slower)", file=sys.stderr)
    scan = run_rg if use_rg else run_python_scan

    root = os.path.abspath(args.root)
    langs = args.lang or sorted(PACKS)

    # (relpath, vclass, lang) -> {"lines": {line: snippet}, "sinks": set()}
    groups = {}
    n_hits = 0
    for lang in langs:
        pack = PACKS[lang]
        for vclass, sink, pattern in pack["rules"]:
            if args.vclasses and vclass not in args.vclasses:
                continue
            for path, line, snippet in scan(root, pack["globs"], pattern):
                rel = os.path.relpath(path, root)
                key = (rel, vclass, lang)
                g = groups.setdefault(key, {"lines": {}, "sinks": set()})
                if line not in g["lines"]:
                    g["lines"][line] = snippet.strip()
                    n_hits += 1
                g["sinks"].add(sink)

    units = []
    for (rel, vclass, lang) in sorted(groups):
        g = groups[(rel, vclass, lang)]
        lines = sorted(g["lines"])
        digest = hashlib.sha1(("%s|%s|%s" % (rel, vclass, lang)).encode()).hexdigest()[:10]
        first = lines[0]
        units.append({
            "id": "taint-%s-%s" % (vclass, digest),
            "title": "Trace %s sink candidate(s) in %s (%d hit%s)"
                     % (vclass, rel, len(lines), "" if len(lines) == 1 else "s"),
            "targets": ["%s:%d" % (rel, ln) for ln in lines[: args.max_targets]],
            "hints": {
                "vuln_class": vclass,
                "sink": "; ".join(sorted(g["sinks"])),
                "language": lang,
                "snippet": g["lines"][first][:240],
            },
        })

    out = json.dumps(units, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    print("sink_hunt: %d hits -> %d work units (%s)"
          % (n_hits, len(units), "stdout" if args.output == "-" else args.output), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
