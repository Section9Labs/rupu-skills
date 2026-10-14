#!/usr/bin/env python3
"""workunits_from_workflows.py - turn mapped application workflows into a
rupu work-units JSON array (one unit per workflow x WSTG-BUSL attack idea)
so a lead agent can dispatch logic testing per workflow, or a rupu workflow
can `for_each:` over the file. Python 3 standard library only.

Input (JSON file or '-' for stdin): either a list of workflow objects or
{"workflows": [...]}. Workflow object shape (all keys optional except name):

  {
    "name": "checkout",
    "targets": ["https://example.com/cart", "https://example.com/checkout"],
    "steps": [
      {"method": "POST", "url": "https://example.com/cart/add"},
      {"method": "POST", "url": "https://example.com/api/coupon/redeem",
       "params": ["code"]},
      {"method": "POST", "url": "https://example.com/checkout/complete"}
    ],
    "features": ["coupon", "payment"],      # free-form tags; "upload" adds
                                            # a file-upload-testing handoff
    "notes": "coupon SAVE10 single-use per account"
  }

Usage:
  python3 scripts/workunits_from_workflows.py workflows.json \
      --work-units busl-units.json

Output: a clean JSON ARRAY (first character '[') of
{"id","title","targets","hints"} elements - hand it to the `work-units`
skill / rupu `for_each:`.  -- vulture (bronze-dune)
"""

import argparse
import json
import re
import sys

ATTACKS = [
    ("busl-01-data-validation", "WSTG-BUSL-01",
     "Tamper business data in {wf}",
     "Negative/zero/overflow quantities and prices, currency and precision "
     "abuse, tamper every client-sent calculated field (price, discount, "
     "tax, total); see references/wstg-busl-cases.md payload set."),
    ("busl-02-forge-requests", "WSTG-BUSL-02",
     "Forge requests the UI never sends in {wf}",
     "Replay with out-of-enum parameter values, guess sibling actions "
     "(cancel->approve/refund/complete), add undocumented parameters "
     "(debug=1, admin=1, discount=100), method swaps, API/mobile parity."),
    ("busl-03-integrity", "WSTG-BUSL-03",
     "Break integrity of server-authoritative values in {wf}",
     "Mass assignment of role/balance/status keys, decode and tamper opaque "
     "blobs (Base64/JWT/signed state), stale-value replay, strip signatures."),
    ("busl-04-race", "WSTG-BUSL-04",
     "Race the check-then-act transitions in {wf}",
     "Fire N synchronized identical requests at single-use/limited actions "
     "(scripts/race_runner.py --sync last-byte, or Turbo Intruder "
     "single-packet); confirm duplicated effect server-side. Also "
     "multi-endpoint races between conflicting steps."),
    ("busl-05-limits", "WSTG-BUSL-05",
     "Exceed function-use limits in {wf}",
     "Serial replay of one-time actions, remove/re-apply lifecycle "
     "laundering, identifier variants (case/space/Unicode), identity "
     "variants (plus-addressing), per-surface limit mismatch (web vs API)."),
    ("busl-06-workflow", "WSTG-BUSL-06",
     "Circumvent the workflow order in {wf}",
     "Call the final step directly (skip payment/verification), reorder "
     "steps (coupon after total lock, cart edit after price fix), repeat "
     "steps, backward transitions, cross-session/cross-user step mixing."),
    ("busl-07-misuse-defenses", "WSTG-BUSL-07",
     "Probe abuse defenses around {wf}",
     "Bulk failed attempts, rapid-fire actions, state-machine-violating "
     "navigation; record whether lockout/CAPTCHA/alerting exists. Absence "
     "amplifies every other BUSL finding."),
]

UPLOAD_HINT = re.compile(r"upload|import|attach|file|avatar|document",
                         re.IGNORECASE)


def slugify(text):
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return slug or "workflow"


def workflow_targets(wf):
    targets = []
    for key in ("targets", "urls"):
        for t in wf.get(key) or []:
            targets.append(t)
    for step in wf.get("steps") or []:
        if isinstance(step, dict) and step.get("url"):
            targets.append(step["url"])
        elif isinstance(step, str):
            m = re.search(r"https?://\S+", step)
            if m:
                targets.append(m.group(0))
    if not targets and wf.get("base_url"):
        targets.append(wf["base_url"])
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def steps_summary(wf):
    parts = []
    for step in wf.get("steps") or []:
        if isinstance(step, dict):
            parts.append("%s %s" % (step.get("method", "GET"),
                                    step.get("url", "?")))
        else:
            parts.append(str(step))
    return " -> ".join(parts)


def has_upload(wf):
    tags = " ".join(str(f) for f in wf.get("features") or [])
    blob = tags + " " + steps_summary(wf) + " " + " ".join(workflow_targets(wf))
    return bool(UPLOAD_HINT.search(blob))


def units_for_workflow(wf):
    name = wf.get("name") or "workflow"
    wf_slug = slugify(name)
    targets = workflow_targets(wf)
    base_hints = {
        "skill": "business-logic-testing",
        "workflow": name,
    }
    steps = steps_summary(wf)
    if steps:
        base_hints["steps"] = steps
    if wf.get("notes"):
        base_hints["notes"] = str(wf["notes"])
    units = []
    for slug, wstg, title_tmpl, attack in ATTACKS:
        hints = dict(base_hints)
        hints["wstg"] = wstg
        hints["attack"] = attack
        units.append({
            "id": "%s-%s" % (wf_slug, slug),
            "title": title_tmpl.format(wf="workflow '%s'" % name),
            "targets": targets,
            "hints": hints,
        })
    if has_upload(wf):
        hints = dict(base_hints)
        hints["skill"] = "file-upload-testing"
        hints["wstg"] = "WSTG-BUSL-08,WSTG-BUSL-09"
        hints["attack"] = ("Workflow accepts files: hand upload mechanics "
                           "(type/content bypass, malicious files) to the "
                           "file-upload-testing skill; keep logic angles "
                           "(import sets price/role, cross-user upload) in "
                           "business-logic-testing.")
        units.append({
            "id": "%s-busl-08-09-upload-handoff" % wf_slug,
            "title": "File-upload testing handoff for workflow '%s'" % name,
            "targets": targets,
            "hints": hints,
        })
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("input", help="workflows JSON file, or '-' for stdin")
    ap.add_argument("--work-units", "-o", metavar="OUT.json",
                    help="write the work-units array here (default: stdout)")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.input == "-" else open(args.input).read()
    data = json.loads(raw)
    if isinstance(data, dict):
        workflows = data.get("workflows", [])
    else:
        workflows = data
    if not isinstance(workflows, list) or not workflows:
        print("error: no workflows found in input", file=sys.stderr)
        sys.exit(2)

    units = []
    for wf in workflows:
        if isinstance(wf, str):
            wf = {"name": wf}
        units.extend(units_for_workflow(wf))

    out = json.dumps(units, indent=2)
    assert out and out[0] == "[", "work-units output must start with '['"
    if args.work_units:
        with open(args.work_units, "w") as fh:
            fh.write(out + "\n")
        print("[+] %d work units (%d workflows) -> %s  "
              "(hand to the work-units skill / rupu for_each:)"
              % (len(units), len(workflows), args.work_units),
              file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
