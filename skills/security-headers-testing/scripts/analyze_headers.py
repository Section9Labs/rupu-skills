#!/usr/bin/env python3
"""analyze_headers.py - security-header and cookie-flag analyzer (stdlib only).

Input: fetch a URL (--url), or parse a saved/piped raw HTTP response (--file / --stdin,
e.g. from `curl -sk -D - -o /dev/null URL`). Grades every security header and every
Set-Cookie against best practice, then emits rupu-ingestible output:

  -o report.json           merged JSON report (all checks)
  --work-units gaps.json   JSON array of work units (one per gap) for for_each/dispatch
  --findings findings.json array of findings.report payloads (scope endpoint/host,
                           WSTG + CWE classification, raw headers as evidence)
  --poc poc.html           clickjacking framing PoC for the target URL

Examples:
  python3 scripts/analyze_headers.py --url https://example.com/ -o report.json \
      --work-units gaps.json --findings findings.json
  curl -sk -D - -o /dev/null https://example.com/account | \
      python3 scripts/analyze_headers.py --stdin \
      --target-url https://example.com/account --sensitive --findings f.json
  python3 scripts/analyze_headers.py --url https://example.com/account --poc poc.html
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

SESSION_NAMES = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|remember|login|jsessionid|phpsessid|"
    r"asp\.net_sessionid|connect\.sid|_rails_session|laravel_session)", re.I)
CSRF_NAMES = re.compile(r"(csrf|xsrf)", re.I)
BYPASS_HOSTS = [
    "googleapis.com", "google.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "yandex.net", "vk.com", "herokuapp.com", "googletagmanager.com",
    "s3.amazonaws.com", "cloudfront.net", "github.io",
]
LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                "x-aspnetmvc-version", "x-generator"]


# ---------------------------------------------------------------- input

def fetch(url, method):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": "Mozilla/5.0",
                                          "Accept": "*/*"})
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
    except urllib.error.HTTPError as e:   # 4xx/5xx still carry headers
        resp = e
    status = "HTTP/1.1 %s %s" % (resp.code, getattr(resp, "reason", "") or "")
    headers = [(k, v) for k, v in resp.headers.items()]
    return status, headers


def parse_raw(text):
    """Parse raw response text; with multiple blocks (curl -D over redirects) use
    the last one. Returns (status_line, [(name, value), ...])."""
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    blocks = [b for b in blocks if re.match(r"HTTP/", b.strip())]
    block = blocks[-1] if blocks else text.strip()
    lines = block.splitlines()
    status = lines[0].strip() if lines else ""
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    return status, headers


def hget(headers, name):
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def hget_all(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


def header_block(status, headers):
    return status + "\r\n" + "\r\n".join("%s: %s" % (k, v) for k, v in headers)


# ---------------------------------------------------------------- checks

def R(check, status, severity, cwe, wstg, detail, value=None):
    return {"check": check, "status": status, "severity": severity,
            "cwe": cwe, "wstg": wstg, "detail": detail, "value": value}


def parse_csp(value):
    d = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks:
            d[toks[0].lower()] = toks[1:]
    return d


def check_csp(headers):
    out = []
    csp = hget(headers, "Content-Security-Policy")
    ro = hget(headers, "Content-Security-Policy-Report-Only")
    if not csp:
        if ro:
            out.append(R("csp", "missing", "medium", "CWE-693", "WSTG-CONF-12",
                         "Only Report-Only CSP present; nothing is enforced", ro))
        else:
            out.append(R("csp", "missing", "medium", "CWE-693", "WSTG-CONF-12",
                         "No Content-Security-Policy header"))
        return out
    d = parse_csp(csp)
    script = d.get("script-src", d.get("default-src", []))
    low = [s.lower() for s in script]
    has_nonce = any(s.startswith("'nonce-") or s.startswith("'sha") for s in low)
    if "'unsafe-inline'" in low and not has_nonce:
        out.append(R("csp-unsafe-inline", "weak", "medium", "CWE-693",
                     "WSTG-CONF-12", "script policy allows 'unsafe-inline' "
                     "without nonce/hash - inline XSS executes", csp))
    if "'unsafe-eval'" in low:
        out.append(R("csp-unsafe-eval", "weak", "low", "CWE-693", "WSTG-CONF-12",
                     "script policy allows 'unsafe-eval'", csp))
    for bad in ("*", "http:", "https:", "data:"):
        if bad in low:
            out.append(R("csp-broad-source", "weak", "medium", "CWE-693",
                         "WSTG-CONF-12",
                         "script policy allows %r - any origin can host payload"
                         % bad, csp))
            break
    gadgets = sorted({h for s in low for h in BYPASS_HOSTS if h in s})
    if gadgets:
        out.append(R("csp-bypassable-allowlist", "weak", "medium", "CWE-693",
                     "WSTG-CONF-12", "allowlisted bypass-gadget host(s): %s "
                     "(JSONP/AngularJS or attacker-registrable)"
                     % ", ".join(gadgets), csp))
    if "object-src" not in d and "default-src" not in d:
        out.append(R("csp-no-object-src", "weak", "low", "CWE-693",
                     "WSTG-CONF-12", "no object-src and no default-src fallback", csp))
    if "base-uri" not in d:
        out.append(R("csp-no-base-uri", "weak", "low", "CWE-693", "WSTG-CONF-12",
                     "no base-uri - <base href> injection re-points relative scripts",
                     csp))
    if not out:
        out.append(R("csp", "ok", "info", "CWE-693", "WSTG-CONF-12",
                     "CSP present with no obvious weakness", csp))
    return out


def check_hsts(headers, is_https):
    v = hget(headers, "Strict-Transport-Security")
    if not is_https:
        return []
    if not v:
        return [R("hsts", "missing", "medium", "CWE-319", "WSTG-CONF-07",
                  "No Strict-Transport-Security on HTTPS response")]
    out = []
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age == 0:
        out.append(R("hsts-max-age", "weak", "medium", "CWE-319", "WSTG-CONF-07",
                     "max-age=0 clears HSTS", v))
    elif age < 15552000:
        out.append(R("hsts-max-age", "weak", "low", "CWE-319", "WSTG-CONF-07",
                     "max-age %d < 15552000 (180 days)" % age, v))
    if "includesubdomains" not in v.lower():
        out.append(R("hsts-subdomains", "weak", "low", "CWE-319", "WSTG-CONF-07",
                     "no includeSubDomains - subdomain strip window", v))
    if "preload" not in v.lower():
        out.append(R("hsts-preload", "info", "info", "CWE-319", "WSTG-CONF-07",
                     "not preload-eligible - first-visit strip window", v))
    if not out:
        out.append(R("hsts", "ok", "info", "CWE-319", "WSTG-CONF-07", "HSTS solid", v))
    return out


def check_frame(headers):
    xfo = hget(headers, "X-Frame-Options")
    csp = hget(headers, "Content-Security-Policy") or ""
    fa = "frame-ancestors" in csp.lower()
    if fa:
        return [R("frameable", "ok", "info", "CWE-1021", "WSTG-CLNT-09",
                  "CSP frame-ancestors set", csp)]
    if not xfo:
        return [R("frameable", "missing", "medium", "CWE-1021", "WSTG-CLNT-09",
                  "No X-Frame-Options and no frame-ancestors - build clickjacking "
                  "PoC (--poc) on state-changing pages")]
    if "allow-from" in xfo.lower() or "," in xfo:
        return [R("frameable", "weak", "medium", "CWE-1021", "WSTG-CLNT-09",
                  "XFO value ignored/invalid in modern browsers: %r" % xfo, xfo)]
    return [R("frameable", "ok", "info", "CWE-1021", "WSTG-CLNT-09", xfo, xfo)]


def check_simple(headers, sensitive):
    out = []
    xcto = hget(headers, "X-Content-Type-Options")
    if not xcto or xcto.lower().strip() != "nosniff":
        out.append(R("x-content-type-options", "missing", "low", "CWE-693",
                     "WSTG-CONF", "nosniff absent - MIME sniffing enabled "
                     "(medium on upload/API routes)", xcto))
    rp = hget(headers, "Referrer-Policy")
    if not rp:
        out.append(R("referrer-policy", "info", "info", "CWE-693", "WSTG-CONF",
                     "absent (browser default applies); weak/low if URLs carry tokens"))
    elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(R("referrer-policy", "weak", "low", "CWE-693", "WSTG-CONF",
                     "leaky policy %r" % rp, rp))
    if not hget(headers, "Permissions-Policy"):
        out.append(R("permissions-policy", "info", "info", "CWE-693", "WSTG-CONF",
                     "absent - feature access ungoverned (hygiene)"))
    acao = hget(headers, "Access-Control-Allow-Origin")
    acac = hget(headers, "Access-Control-Allow-Credentials")
    if acao:
        sev = "medium" if (acac or "").lower() == "true" else "low"
        out.append(R("cors", "weak", sev, "CWE-942", "WSTG-CONF",
                     "ACAO=%r ACAC=%r - hand off to cors-testing skill"
                     % (acao, acac), acao))
    if sensitive:
        cc = (hget(headers, "Cache-Control") or "").lower()
        if not cc:
            out.append(R("cache-control", "missing", "medium", "CWE-525",
                         "WSTG-ATHN-06", "no Cache-Control on sensitive response"))
        elif "no-store" not in cc:
            sev = "medium" if ("public" in cc or re.search(r"max-age=[1-9]", cc)) \
                else "low"
            out.append(R("cache-control", "weak", sev, "CWE-525", "WSTG-ATHN-06",
                         "sensitive response storable: %r" % cc, cc))
    leaks = ["%s: %s" % (k, v) for k, v in headers if k.lower() in LEAK_HEADERS
             and re.search(r"\d", v)]
    if leaks:
        out.append(R("version-leak", "info", "info", "CWE-200", "WSTG-INFO-02",
                     "version strings leaked: %s" % "; ".join(leaks)))
    xxp = hget(headers, "X-XSS-Protection")
    if xxp and xxp.strip() != "0":
        out.append(R("x-xss-protection", "info", "info", "CWE-693", "WSTG-CONF",
                     "deprecated header enabled (%r) - XS-Leaks on legacy browsers; "
                     "recommend 0/removal + CSP" % xxp, xxp))
    loc = hget(headers, "Location")
    if loc:
        out.append(R("crlf-candidate", "info", "info", "CWE-93", "WSTG-INPV",
                     "redirect present (Location: %s) - hand to open-redirect-testing "
                     "skill (Oralyzer -crlf) if any part is input-derived" % loc, loc))
    return out


def check_cookies(headers, is_https):
    out = []
    for raw in hget_all(headers, "Set-Cookie"):
        first, _, rest = raw.partition(";")
        name = first.split("=", 1)[0].strip()
        attrs = {}
        for a in rest.split(";"):
            k, _, v = a.strip().partition("=")
            if k:
                attrs[k.lower()] = v.strip()
        is_sess = bool(SESSION_NAMES.search(name)) and not CSRF_NAMES.search(name)
        role = "session" if is_sess else "other"
        base_sev = "medium" if is_sess else "low"
        gaps = []
        if "httponly" not in attrs and not CSRF_NAMES.search(name):
            gaps.append(("httponly", base_sev, "CWE-1004", "no HttpOnly"))
        if is_https and "secure" not in attrs and not name.startswith("__Host-"):
            gaps.append(("secure", base_sev, "CWE-614", "no Secure"))
        ss = attrs.get("samesite", "").lower()
        if not ss:
            gaps.append(("samesite", "low", "CWE-1275", "no SameSite"))
        elif ss == "none":
            gaps.append(("samesite", base_sev, "CWE-1275", "SameSite=None"))
        dom = attrs.get("domain")
        if dom and dom.lstrip(".").count(".") >= 1:
            gaps.append(("domain", base_sev, "CWE-1275",
                         "broad Domain=%s shared with all subdomains" % dom))
        if is_sess and not name.startswith(("__Host-", "__Secure-")):
            gaps.append(("prefix", "info", "CWE-693",
                         "session cookie lacks __Host-/__Secure- prefix"))
        for gkey, sev, cwe, msg in gaps:
            out.append(R("cookie-%s-%s" % (name, gkey),
                         "info" if sev == "info" else "weak", sev, cwe,
                         "WSTG-SESS-02", "%s cookie %r: %s" % (role, name, msg), raw))
        if not gaps:
            out.append(R("cookie-%s" % name, "ok", "info", "CWE-693",
                         "WSTG-SESS-02", "cookie %r well-flagged" % name, raw))
    return out


# ---------------------------------------------------------------- output

POC = """<!doctype html><title>cj-poc</title>
<style>iframe.a{position:absolute;top:-80px;left:-20px;width:900px;height:600px;
opacity:0.4;z-index:2;border:0}button{position:absolute;top:140px;left:210px;
z-index:1;font-size:22px}</style>
<button>CLAIM FREE PRIZE</button>
<iframe class=a src="%(u)s"></iframe>
<hr style="margin-top:650px">
<p>framebuster-bypass variant (sandbox blocks top-navigation busters):</p>
<iframe src="%(u)s" sandbox="allow-forms allow-scripts"
 style="width:900px;height:300px"></iframe>
"""


def to_work_units(results, url, host):
    units = []
    for r in results:
        if r["status"] in ("ok",):
            continue
        units.append({
            "id": "hdr-%s-%s" % (r["check"], host),
            "title": "%s %s on %s" % (r["check"], r["status"], url),
            "targets": [url],
            "hints": {"check": r["check"], "status": r["status"],
                      "severity": r["severity"], "detail": r["detail"],
                      "value": r.get("value") or "",
                      "next": "verify/exploit per security-headers-testing references"},
        })
    return units


def to_findings(results, url, evidence_block):
    out = []
    for r in results:
        if r["status"] in ("ok", "info") and r["severity"] == "info":
            continue
        if r["status"] == "ok":
            continue
        out.append({
            "title": "%s: %s" % (r["check"], r["detail"][:80]),
            "scope": "endpoint",
            "target_ref": url,
            "severity": r["severity"],
            "classification": {"cwe": r["cwe"], "owasp": r["wstg"]},
            "evidence": {
                "rationale": "%s. Observed value: %r" % (r["detail"],
                                                         r.get("value")),
                "http_exchange": "GET %s\n\n%s" % (url, evidence_block),
                "artifacts": [],
            },
        })
    return out


def main():
    ap = argparse.ArgumentParser(description="Security header / cookie analyzer")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="fetch this URL")
    src.add_argument("--file", help="parse raw HTTP response from file")
    src.add_argument("--stdin", action="store_true", help="parse raw response from stdin")
    ap.add_argument("--target-url", help="URL label for --file/--stdin input")
    ap.add_argument("--method", default="GET", choices=["GET", "HEAD"])
    ap.add_argument("--sensitive", action="store_true",
                    help="treat response as sensitive (enable cache checks)")
    ap.add_argument("-o", "--output", help="write merged JSON report")
    ap.add_argument("--work-units", metavar="FILE", help="write work-units array")
    ap.add_argument("--findings", metavar="FILE",
                    help="write findings.report payload array")
    ap.add_argument("--poc", metavar="FILE", help="write clickjacking PoC html")
    args = ap.parse_args()

    if args.url:
        url = args.url
        status, headers = fetch(url, args.method)
    else:
        url = args.target_url or "https://example.com/"
        text = sys.stdin.read() if args.stdin else open(args.file).read()
        status, headers = parse_raw(text)

    is_https = url.lower().startswith("https")
    host = urllib.parse.urlsplit(url).hostname or "target"

    results = []
    results += check_csp(headers)
    results += check_hsts(headers, is_https)
    results += check_frame(headers)
    results += check_simple(headers, args.sensitive)
    results += check_cookies(headers, is_https)

    block = header_block(status, headers)
    report = {"url": url, "status_line": status, "results": results,
              "asset": {"kind": "web:route",
                        "coordinates": [{"t": "url", "v": url},
                                        {"t": "http_route",
                                         "v": urllib.parse.urlsplit(url).path or "/"}],
                        "label": "%s (headers graded)" % url, "depth": "tested"}}

    for r in results:
        print("[%-7s] %-9s %-32s %s" %
              (r["status"], r["severity"], r["check"], r["detail"]))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print("[+] report -> %s" % args.output)
    if args.work_units:
        units = to_work_units(results, url, host)
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        print("[+] %d work unit(s) -> %s" % (len(units), args.work_units))
    if args.findings:
        fnd = to_findings(results, url, block)
        with open(args.findings, "w") as f:
            json.dump(fnd, f, indent=2)
        print("[+] %d finding payload(s) -> %s" % (len(fnd), args.findings))
    if args.poc:
        with open(args.poc, "w") as f:
            f.write(POC % {"u": url})
        print("[+] clickjacking PoC -> %s (serve via python3 -m http.server, "
              "open from a different origin)" % args.poc)
    if not (args.output or args.work_units or args.findings):
        json.dump(report, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
