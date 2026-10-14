#!/usr/bin/env python3
"""flow_abuse.py - replay a multi-step business flow N times (API6:2023).

Reads a JSON flow template (sequence of request steps with {{var}}
substitution and regex extraction between steps), runs it for N iterations,
and reports successes per iteration plus whether any friction (429, captcha,
lockout, failed step) stopped it.

Example:
  python3 scripts/flow_abuse.py --flow flows/signup-referral.json \
      --iterations 50 --delay 0.2 \
      --out reports/flow-signup.json --units reports/flow-signup-units.json

Flow file format (see references/business-flows.md for a worked example):
{
  "name": "signup-referral-farm",
  "variables": {"base": "https://api.example.com"},
  "steps": [
    {"name": "signup", "method": "POST", "url": "{{base}}/v1/signup",
     "headers": {"Content-Type": "application/json"},
     "body": "{\\"email\\":\\"probe+{{i}}@example.net\\",\\"password\\":\\"S9!{{uuid}}\\"}",
     "extract": {"token": "\\"access_token\\"\\\\s*:\\\\s*\\"([^\\"]+)\\""},
     "success": {"status": [200, 201], "body_regex": null}}
  ]
}

Builtins regenerated each iteration: {{i}}, {{rand}}, {{rand_hex}}, {{uuid}},
{{ts}}. `extract` regexes (group 1 captured) populate variables for later
steps of the same iteration.
"""

import argparse
import json
import os
import random
import re
import ssl
import string
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

CAPTCHA_MARKERS = re.compile(
    r"captcha|recaptcha|hcaptcha|turnstile|challenge[-_ ]?required|"
    r"are you a robot|unusual activity", re.IGNORECASE)

VAR_RE = re.compile(r"\{\{(\w+)\}\}")


def substitute(template, variables):
    if template is None:
        return None

    def repl(match):
        return variables.get(match.group(1), match.group(0))

    return VAR_RE.sub(repl, template)


def iteration_builtins(i):
    return {
        "i": str(i),
        "rand": "".join(random.choices(string.ascii_lowercase + string.digits,
                                       k=8)),
        "rand_hex": uuid.uuid4().hex[:12],
        "uuid": str(uuid.uuid4()),
        "ts": str(int(time.time())),
    }


def send(step, variables, timeout, ctx):
    url = substitute(step["url"], variables)
    method = step.get("method", "GET").upper()
    body = substitute(step.get("body"), variables)
    data = body.encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for name, value in (step.get("headers") or {}).items():
        req.add_header(name, substitute(value, variables))
    start = time.monotonic()
    status, text, err = 0, "", None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            status = r.status
            text = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - network errors are data here
        err = type(e).__name__
    ms = round((time.monotonic() - start) * 1000.0, 1)
    return {"url": url, "method": method, "status": status, "ms": ms,
            "body": text, "error": err}


def step_ok(step, result):
    if result["error"]:
        return False
    crit = step.get("success") or {}
    statuses = crit.get("status")
    if statuses:
        if result["status"] not in statuses:
            return False
    elif not (200 <= result["status"] < 400):
        return False
    body_re = crit.get("body_regex")
    if body_re and not re.search(body_re, result["body"]):
        return False
    return True


def classify_friction(result):
    if result["status"] in (429, 420):
        return "throttle-429"
    if result["status"] == 503:
        return "overload-503"
    if result["status"] in (401, 403) :
        return "blocked-%d" % result["status"]
    if CAPTCHA_MARKERS.search(result["body"] or ""):
        return "captcha-marker"
    if result["error"]:
        return "transport-error"
    return "step-failed"


def run_iteration(flow, i, timeout, ctx):
    variables = dict(flow.get("variables") or {})
    variables.update(iteration_builtins(i))
    steps_out = []
    for step in flow["steps"]:
        result = send(step, variables, timeout, ctx)
        ok = step_ok(step, result)
        captcha = bool(CAPTCHA_MARKERS.search(result["body"] or ""))
        record = {"step": step.get("name", step["url"]),
                  "status": result["status"], "ms": result["ms"],
                  "ok": ok, "captcha_marker": captcha,
                  "error": result["error"]}
        if ok:
            for var, pattern in (step.get("extract") or {}).items():
                m = re.search(pattern, result["body"])
                if m:
                    variables[var] = m.group(1)
                else:
                    record["extract_missed"] = var
        else:
            record["friction"] = classify_friction(result)
            record["body_snippet"] = (result["body"] or "")[:400]
        steps_out.append(record)
        if not ok:
            return {"i": i, "ok": False, "steps": steps_out,
                    "friction": record["friction"],
                    "failed_step": record["step"]}
    return {"i": i, "ok": True, "steps": steps_out}


def write_atomic(path, obj):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def build_units(flow, verdict, first_block, hints_extra):
    targets = []
    for step in flow["steps"]:
        raw_url = step["url"]
        route = "%s %s" % (step.get("method", "GET").upper(),
                           urllib.parse.urlsplit(
                               raw_url.replace("{{base}}", "")).path or
                           raw_url)
        targets.append(route[:200])
    title = "flow-no-friction" if verdict == "no-friction" else "flow-friction"
    hints = list(hints_extra or [])
    if verdict == "no-friction":
        hints.append("captcha-absent")
    return [{
        "id": slugify("flow-" + flow.get("name", "unnamed")),
        "title": title,
        "targets": targets[:10],
        "hints": sorted(set(hints)),
    }]


def main():
    ap = argparse.ArgumentParser(
        description="replay a multi-step business flow N times")
    ap.add_argument("--flow", required=True, help="flow template JSON file")
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between iterations")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--continue-on-block", action="store_true",
                    help="keep iterating after friction fires (default: stop "
                         "at first block to characterize it)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--hint", action="append", default=[],
                    help="extra fixed-vocabulary hint for emitted units")
    ap.add_argument("--out", default=None, help="write JSON report here")
    ap.add_argument("--units", default=None,
                    help="write rupu work-unit JSON array here")
    args = ap.parse_args()

    with open(args.flow) as fh:
        flow = json.load(fh)
    if "steps" not in flow or not flow["steps"]:
        raise SystemExit("flow file has no steps")

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    started = time.monotonic()
    iterations = []
    first_block = None
    for i in range(args.iterations):
        result = run_iteration(flow, i, args.timeout, ctx)
        iterations.append(result)
        marker = "ok" if result["ok"] else (
            "BLOCKED(%s@%s)" % (result["friction"], result["failed_step"]))
        print("[%03d] %s" % (i, marker), file=sys.stderr)
        if not result["ok"] and first_block is None:
            first_block = {"iteration": i,
                           "step": result["failed_step"],
                           "friction": result["friction"]}
            if not args.continue_on_block:
                break
        if args.delay:
            time.sleep(args.delay)
    elapsed = round(time.monotonic() - started, 1)

    successes = sum(1 for r in iterations if r["ok"])
    captcha_seen = any(s.get("captcha_marker")
                       for r in iterations for s in r["steps"])
    if first_block is None and successes == args.iterations:
        verdict = "no-friction"
    elif first_block is not None:
        verdict = "friction-at-%d" % first_block["iteration"]
    else:
        verdict = "incomplete"

    report = {
        "tool": "flow_abuse",
        "flow": flow.get("name", os.path.basename(args.flow)),
        "iterations_requested": args.iterations,
        "iterations_run": len(iterations),
        "successes": successes,
        "elapsed_s": elapsed,
        "verdict": verdict,
        "first_block": first_block,
        "captcha_marker_seen": captcha_seen,
        "iterations": iterations,
    }

    if args.out:
        write_atomic(args.out, report)
        print("[+] report: %s" % args.out, file=sys.stderr)
    if args.units:
        base_verdict = "no-friction" if verdict == "no-friction" else "friction"
        units = build_units(flow, base_verdict, first_block, args.hint)
        write_atomic(args.units, units)
        print("[+] units: %s (%d)" % (args.units, len(units)),
              file=sys.stderr)

    print(json.dumps({"verdict": verdict, "successes": successes,
                      "iterations_run": len(iterations),
                      "elapsed_s": elapsed,
                      "first_block": first_block,
                      "captcha_marker_seen": captcha_seen}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
