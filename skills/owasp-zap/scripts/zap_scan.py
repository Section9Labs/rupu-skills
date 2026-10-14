#!/usr/bin/env python3
"""zap_scan.py - drive the OWASP ZAP REST API end to end (stdlib only).

Spider -> (optional AJAX spider) -> passive-scan drain -> active scan ->
pull all alerts -> normalize -> emit:
  --out          merged normalized alerts JSON
  --work-units   rupu work-units JSON ARRAY (first char '['), one unit per
                 alert type, for the `work-units` skill / for_each fan-out
  --findings     findings.report payload array (scope endpoint, severity
                 mapped from ZAP risk, CWE + WSTG classification, HTTP
                 exchange evidence) for the `finding-report` skill

Example:
  python3 scripts/zap_scan.py --zap http://127.0.0.1:8090 --api-key KEY \
      --target https://app.example.com --ajax \
      --out alerts.json --work-units wu.json --findings findings.json
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}

# Minimal CWE -> WSTG mapping for common ZAP alerts; CWE always included too.
CWE_TO_WSTG = {
    "89": "WSTG-INPV-05", "79": "WSTG-INPV-01", "78": "WSTG-INPV-12",
    "22": "WSTG-ATHZ-01", "98": "WSTG-INPV-11", "611": "WSTG-INPV-07",
    "918": "WSTG-INPV-19", "601": "WSTG-CLNT-04", "352": "WSTG-SESS-05",
    "614": "WSTG-SESS-02", "1004": "WSTG-SESS-02", "16": "WSTG-CONF-02",
    "693": "WSTG-CONF-12", "319": "WSTG-CRYP-03", "200": "WSTG-INFO-05",
    "209": "WSTG-ERRH-01", "548": "WSTG-CONF-04", "97": "WSTG-INPV-18",
    "94": "WSTG-INPV-18", "113": "WSTG-INPV-15", "90": "WSTG-INPV-06",
}

NEXT_TOOL = {
    "89": "sqlmap -u <target> -p <param> --batch --level=2 --risk=2",
    "79": "dalfox scan <target> -p <param> -f json",
    "22": "lfimap -U <target> -a",
    "601": "oralyzer -u <target>",
    "918": "interactsh-client + manual SSRF probing",
}


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:60] or "alert"


class ZapClient:
    def __init__(self, base, apikey, timeout=60):
        self.base = base.rstrip("/")
        self.apikey = apikey
        self.timeout = timeout

    def call(self, component, kind, name, **params):
        params = {k: v for k, v in params.items() if v is not None}
        if self.apikey:
            params["apikey"] = self.apikey
        url = "%s/JSON/%s/%s/%s/?%s" % (
            self.base, component, kind, name, urllib.parse.urlencode(params))
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    def view(self, component, name, **params):
        return self.call(component, "view", name, **params)

    def action(self, component, name, **params):
        return self.call(component, "action", name, **params)


def poll(fn, done, label, interval, max_wait):
    start = time.time()
    while True:
        val = fn()
        sys.stderr.write("[*] %s: %s\n" % (label, val))
        if done(val):
            return True
        if time.time() - start > max_wait:
            sys.stderr.write("[!] %s: timed out after %ss, continuing\n" % (label, max_wait))
            return False
        time.sleep(interval)


def run_spider(zap, args):
    params = {"url": args.target, "recurse": "true"}
    if args.context_id is not None and args.user_id is not None:
        res = zap.action("spider", "scanAsUser", contextId=args.context_id,
                         userId=args.user_id, url=args.target, recurse="true")
    else:
        if args.context:
            params["contextName"] = args.context
        res = zap.action("spider", "scan", **params)
    sid = res.get("scan") or res.get("scanAsUser")
    sys.stderr.write("[+] spider started, scanId=%s\n" % sid)
    poll(lambda: int(zap.view("spider", "status", scanId=sid).get("status", 0)),
         lambda v: v >= 100, "spider", 2, args.max_wait)
    urls = zap.view("core", "urls", baseurl=args.target).get("urls", [])
    sys.stderr.write("[+] spider done: %d urls known\n" % len(urls))
    return urls


def run_ajax_spider(zap, args):
    zap.action("ajaxSpider", "scan", url=args.target,
               contextName=args.context, subtreeOnly="true")
    sys.stderr.write("[+] ajax spider started\n")
    poll(lambda: zap.view("ajaxSpider", "status").get("status", ""),
         lambda v: v == "stopped", "ajaxSpider", 5, args.max_wait)


def wait_passive(zap, args):
    poll(lambda: int(zap.view("pscan", "recordsToScan").get("recordsToScan", 0)),
         lambda v: v == 0, "passive queue", 2, args.max_wait)


def run_active(zap, args):
    if args.context_id is not None and args.user_id is not None:
        res = zap.action("ascan", "scanAsUser", contextId=args.context_id,
                         userId=args.user_id, url=args.target, recurse="true",
                         scanPolicyName=args.scan_policy)
    else:
        res = zap.action("ascan", "scan", url=args.target, recurse="true",
                         inScopeOnly="false", scanPolicyName=args.scan_policy)
    sid = res.get("scan") or res.get("scanAsUser")
    sys.stderr.write("[+] active scan started, scanId=%s\n" % sid)
    poll(lambda: int(zap.view("ascan", "status", scanId=sid).get("status", 0)),
         lambda v: v >= 100, "ascan", 5, args.max_wait)


def pull_alerts(zap, baseurl):
    alerts, start, page = [], 0, 500
    while True:
        batch = zap.view("core", "alerts", baseurl=baseurl,
                         start=start, count=page).get("alerts", [])
        alerts.extend(batch)
        if len(batch) < page:
            return alerts
        start += page


def normalize(raw):
    risk = (raw.get("risk") or raw.get("riskdesc") or "").split("(")[0].strip()
    return {
        "alert": raw.get("alert") or raw.get("name") or "",
        "risk": risk,
        "severity": RISK_TO_SEVERITY.get(risk.lower(), "info"),
        "confidence": raw.get("confidence", ""),
        "url": raw.get("url", ""),
        "method": raw.get("method", ""),
        "param": raw.get("param", ""),
        "attack": raw.get("attack", ""),
        "evidence": raw.get("evidence", ""),
        "otherinfo": raw.get("other") or raw.get("otherinfo") or "",
        "cweid": str(raw.get("cweid", "") or ""),
        "wascid": str(raw.get("wascid", "") or ""),
        "pluginId": str(raw.get("pluginId") or raw.get("pluginid") or ""),
        "alertRef": raw.get("alertRef", ""),
        "description": (raw.get("description") or raw.get("desc") or "")[:2000],
        "solution": (raw.get("solution") or "")[:1000],
        "messageId": raw.get("messageId", ""),
    }


def dedupe(alerts):
    seen, out = set(), []
    for a in alerts:
        key = (a["pluginId"], a["alert"], a["url"], a["param"])
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def build_work_units(alerts):
    groups = {}
    for a in alerts:
        if a["confidence"].lower() == "false positive":
            continue
        key = (a["pluginId"], a["alert"])
        groups.setdefault(key, []).append(a)
    units = []
    for (pid, name), items in sorted(groups.items()):
        first = items[0]
        params = sorted({i["param"] for i in items if i["param"]})
        units.append({
            "id": "zap-%s-%s" % (pid or "0", slugify(name)),
            "title": "%s (ZAP plugin %s, risk %s)" % (name, pid, first["risk"]),
            "targets": sorted({i["url"] for i in items if i["url"]})[:50],
            "hints": {
                "pluginId": pid,
                "alert": name,
                "risk": first["risk"],
                "confidence": first["confidence"],
                "cweid": first["cweid"],
                "wascid": first["wascid"],
                "params": ",".join(params)[:500],
                "sample_attack": first["attack"][:500],
                "sample_evidence": first["evidence"][:500],
                "next_tool": NEXT_TOOL.get(first["cweid"], "manual replay / request editor"),
            },
        })
    return units


def build_findings(alerts, zap=None):
    findings = []
    for a in alerts:
        if a["confidence"].lower() == "false positive":
            continue
        exchange = None
        if zap is not None and a.get("messageId"):
            try:
                msg = zap.view("core", "message", id=a["messageId"]).get("message", {})
                exchange = "%s%s\n\n%s%s" % (
                    msg.get("requestHeader", ""), msg.get("requestBody", ""),
                    msg.get("responseHeader", ""),
                    (msg.get("responseBody", "") or "")[:2000])
            except Exception:
                exchange = None
        if not exchange:
            exchange = ("%s %s HTTP/1.1\nattack: %s\n\n"
                        "HTTP/1.1 (see ZAP history)\nevidence fragment: %s") % (
                a["method"] or "GET", a["url"], a["attack"] or "-",
                a["evidence"] or "-")
        title = a["alert"]
        if a["param"]:
            title += " in '%s' parameter" % a["param"]
        classification = {}
        if a["cweid"]:
            classification["cwe"] = "CWE-%s" % a["cweid"]
            if a["cweid"] in CWE_TO_WSTG:
                classification["owasp"] = CWE_TO_WSTG[a["cweid"]]
        findings.append({
            "title": title,
            "scope": "endpoint",
            "target_ref": a["url"],
            "severity": a["severity"],
            "classification": classification or {"cwe": "CWE-0"},
            "evidence": {
                "rationale": ("ZAP plugin %s raised '%s' (risk %s, confidence %s)"
                              " on %s%s. %s") % (
                    a["pluginId"], a["alert"], a["risk"], a["confidence"],
                    a["url"],
                    " param '%s'" % a["param"] if a["param"] else "",
                    a["description"][:400]),
                "http_exchange": exchange,
                "attack": a["attack"],
                "response_evidence": a["evidence"],
                "zap": {"pluginId": a["pluginId"], "alertRef": a["alertRef"],
                        "risk": a["risk"], "confidence": a["confidence"],
                        "wascid": a["wascid"]},
                "solution": a["solution"],
            },
        })
    return findings


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    sys.stderr.write("[+] wrote %s\n" % path)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zap", default="http://127.0.0.1:8090",
                    help="ZAP API base URL (default http://127.0.0.1:8090)")
    ap.add_argument("--api-key", default="", help="ZAP API key")
    ap.add_argument("--target", required=True, help="target base URL")
    ap.add_argument("--ajax", action="store_true", help="also run the AJAX spider")
    ap.add_argument("--no-spider", action="store_true", help="skip the spider")
    ap.add_argument("--no-active", action="store_true",
                    help="skip the active scan (passive-only)")
    ap.add_argument("--scan-policy", default=None, help="active scan policy name")
    ap.add_argument("--context", default=None, help="context name for spidering")
    ap.add_argument("--context-id", default=None, help="contextId for scanAsUser")
    ap.add_argument("--user-id", default=None, help="userId for scanAsUser")
    ap.add_argument("--max-wait", type=int, default=7200,
                    help="max seconds to wait per phase (default 7200)")
    ap.add_argument("--out", default=None, help="write normalized alerts JSON")
    ap.add_argument("--work-units", default=None,
                    help="write rupu work-units JSON array")
    ap.add_argument("--findings", default=None,
                    help="write findings.report payload array")
    args = ap.parse_args()

    zap = ZapClient(args.zap, args.api_key)
    try:
        ver = zap.view("core", "version")
        sys.stderr.write("[+] connected to ZAP %s at %s\n"
                         % (ver.get("version", "?"), args.zap))
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write("[!] cannot reach ZAP API at %s: %s\n" % (args.zap, exc))
        sys.exit(3)

    zap.action("core", "accessUrl", url=args.target)
    if not args.no_spider:
        run_spider(zap, args)
    if args.ajax:
        run_ajax_spider(zap, args)
    wait_passive(zap, args)
    if not args.no_active:
        run_active(zap, args)
        wait_passive(zap, args)

    alerts = dedupe([normalize(a) for a in pull_alerts(zap, args.target)])
    sys.stderr.write("[+] %d unique alerts\n" % len(alerts))

    if args.out:
        write_json(args.out, alerts)
    if args.work_units:
        write_json(args.work_units, build_work_units(alerts))
    if args.findings:
        write_json(args.findings, build_findings(alerts, zap))
    if not (args.out or args.work_units or args.findings):
        json.dump(alerts, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
