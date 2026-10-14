#!/usr/bin/env python3
"""parse_zap_report.py - normalize a ZAP report file (stdlib only).

Accepts the traditional-json report (from `-J report.json`, the Automation
Framework `report` job with template traditional-json, or
/OTHER/core/other/jsonreport/) OR the traditional XML report (`-x`).

Emits the same outputs as zap_scan.py:
  --out          normalized alerts JSON
  --work-units   rupu work-units JSON ARRAY (first char '[') for the
                 `work-units` skill / for_each fan-out
  --findings     findings.report payload array for the `finding-report` skill

Example:
  python3 scripts/parse_zap_report.py report.json \
      --out alerts.json --work-units wu.json --findings findings.json
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}
RISKCODE = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
CONFCODE = {"3": "High", "2": "Medium", "1": "Low", "0": "False Positive"}

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


def strip_tags(text):
    return re.sub(r"<[^>]+>", "", text or "").strip()


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def risk_name(item):
    rd = item.get("riskdesc") or ""
    if rd:
        return rd.split("(")[0].strip()
    return RISKCODE.get(str(item.get("riskcode", "")), "Informational")


def conf_name(item):
    c = str(item.get("confidence", ""))
    return CONFCODE.get(c, c)


def flatten_item(item, instance):
    risk = risk_name(item)
    return {
        "alert": item.get("alert") or item.get("name") or "",
        "risk": risk,
        "severity": RISK_TO_SEVERITY.get(risk.lower(), "info"),
        "confidence": conf_name(item),
        "url": instance.get("uri") or instance.get("url") or "",
        "method": instance.get("method", ""),
        "param": instance.get("param", ""),
        "attack": instance.get("attack", ""),
        "evidence": instance.get("evidence", ""),
        "otherinfo": instance.get("otherinfo", ""),
        "cweid": str(item.get("cweid", "") or ""),
        "wascid": str(item.get("wascid", "") or ""),
        "pluginId": str(item.get("pluginid") or item.get("pluginId") or ""),
        "alertRef": item.get("alertRef", ""),
        "description": strip_tags(item.get("desc") or item.get("description"))[:2000],
        "solution": strip_tags(item.get("solution"))[:1000],
        "messageId": "",
    }


def parse_json_report(data):
    alerts = []
    for site in as_list(data.get("site")):
        for item in as_list(site.get("alerts")):
            instances = as_list(item.get("instances")) or [{}]
            for inst in instances:
                alerts.append(flatten_item(item, inst))
    return alerts


def el_dict(elem):
    d = dict(elem.attrib)
    for child in elem:
        if len(child):
            continue
        d[child.tag] = child.text or ""
    return d


def parse_xml_report(root):
    alerts = []
    for site in root.findall("site"):
        for item in site.findall(".//alertitem"):
            idict = el_dict(item)
            instances = item.find("instances")
            insts = ([el_dict(i) for i in instances.findall("instance")]
                     if instances is not None else [{}])
            for inst in (insts or [{}]):
                alerts.append(flatten_item(idict, inst))
    return alerts


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


def build_findings(alerts):
    findings = []
    for a in alerts:
        if a["confidence"].lower() == "false positive":
            continue
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
    ap.add_argument("report", help="ZAP report file (traditional JSON or XML)")
    ap.add_argument("--out", default=None, help="write normalized alerts JSON")
    ap.add_argument("--work-units", default=None,
                    help="write rupu work-units JSON array")
    ap.add_argument("--findings", default=None,
                    help="write findings.report payload array")
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read().lstrip("\ufeff \t\r\n")

    if raw.startswith("{"):
        alerts = parse_json_report(json.loads(raw))
    elif raw.startswith("<"):
        alerts = parse_xml_report(ET.fromstring(raw))
    else:
        sys.stderr.write("[!] unrecognized report format (expect JSON or XML)\n")
        sys.exit(2)

    alerts = dedupe(alerts)
    sys.stderr.write("[+] %d unique alert instances\n" % len(alerts))

    if args.out:
        write_json(args.out, alerts)
    if args.work_units:
        write_json(args.work_units, build_work_units(alerts))
    if args.findings:
        write_json(args.findings, build_findings(alerts))
    if not (args.out or args.work_units or args.findings):
        json.dump(alerts, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
