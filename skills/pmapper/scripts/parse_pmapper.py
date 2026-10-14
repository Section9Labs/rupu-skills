#!/usr/bin/env python3
"""parse_pmapper.py - run/parse PMapper privesc output into rupu work units.

Runs `pmapper query "preset privesc *"` (JSON first, text fallback) or parses a
saved dump (analysis --output-type json, or query text output), then writes:
  * a bare JSON array of work units  -> --output  (default out/work-units.json)
  * a JSON list of principal assets  -> --assets  (default out/assets.json)

Work unit shape (rupu `work-units` skill):
  {"id","title","targets":[source_arn, target_arn],"hints":{...}}

Examples:
  python3 scripts/parse_pmapper.py --profile target
  python3 scripts/parse_pmapper.py --input out/pmapper-analysis.json
  python3 scripts/parse_pmapper.py --input out/privesc.txt --account 198765432100
"""
import argparse
import json
import os
import re
import subprocess
import sys

ARN_RE = re.compile(r"arn:aws:iam::(\d{12}):(?:user|role)/[\w+=,.@/-]+")
SHORT_PRINCIPAL_RE = re.compile(r"\b((?:user|role)/[\w+=,.@-][\w+=,.@/-]*)")
ESCALATE_RE = re.compile(
    r"^(?P<src>\S.*?) can escalate privileges by accessing the administrative "
    r"principal (?P<dst>.*?):?\s*$"
)
NO_ESCALATE_RE = re.compile(r"cannot escalate privileges")

# phrases in edge descriptions -> canonical method label
METHOD_HINTS = [
    ("sts:assumerole", "sts:AssumeRole"),
    ("assume", "sts:AssumeRole"),
    ("create an access key", "iam:CreateAccessKey"),
    ("access key", "iam:CreateAccessKey"),
    ("login profile", "iam:CreateLoginProfile/UpdateLoginProfile"),
    ("lambda", "iam:PassRole + lambda:CreateFunction"),
    ("function code", "lambda:UpdateFunctionCode"),
    ("instance profile", "iam:PassRole + ec2:RunInstances"),
    ("ec2", "iam:PassRole + ec2:RunInstances"),
    ("cloudformation", "iam:PassRole + cloudformation:CreateStack"),
    ("codebuild", "iam:PassRole + codebuild:CreateProject"),
    ("sagemaker", "iam:PassRole + sagemaker:CreateNotebookInstance"),
    ("glue", "iam:PassRole + glue:CreateDevEndpoint"),
    ("ssm", "ssm:SendCommand/StartSession"),
    ("policy version", "iam:CreatePolicyVersion"),
    ("attach", "iam:AttachUserPolicy/AttachRolePolicy"),
    ("put", "iam:PutUserPolicy/PutRolePolicy"),
    ("group", "iam:AddUserToGroup"),
    ("trust", "iam:UpdateAssumeRolePolicy"),
]


def guess_method(edges):
    text = " ".join(edges).lower()
    for needle, label in METHOD_HINTS:
        if needle in text:
            return label
    return "unknown (see edges)"


def principals_in(text):
    found = [m.group(0) for m in ARN_RE.finditer(text)]
    found += SHORT_PRINCIPAL_RE.findall(text)
    seen, out = set(), []
    for p in found:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def arnify(principal, account):
    """Expand user/x or role/x to a full ARN when the account id is known."""
    if principal.startswith("arn:") or not account:
        return principal
    return "arn:aws:iam::%s:%s" % (account, principal)


def run_pmapper(profile, account):
    base = ["pmapper"]
    if profile:
        base += ["--profile", profile]
    elif account:
        base += ["--account", account]
    # Try JSON output first; older releases only emit text -> fall back.
    for extra in (["--output-type", "json"], []):
        cmd = base + ["query", "preset privesc *"] + extra
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            sys.exit("[!] pmapper not found on PATH (pip install principalmapper)")
        except subprocess.TimeoutExpired:
            sys.exit("[!] pmapper timed out")
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
        sys.stderr.write("[*] retrying without %s (rc=%s)\n" % (extra, proc.returncode))
    sys.exit("[!] pmapper query failed: %s" % proc.stderr.strip()[:500])


def parse_text(text, account):
    """Parse `preset privesc *` text output into (units, principals)."""
    units, principals = [], set()
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = ESCALATE_RE.match(line.strip()) if not raw.startswith((" ", "\t")) else None
        if m and not NO_ESCALATE_RE.search(line):
            if current:
                units.append(current)
            src, dst = m.group("src").strip(), m.group("dst").strip()
            principals.update([src, dst])
            current = {"src": src, "dst": dst, "edges": []}
        elif raw.startswith((" ", "\t")) and current is not None:
            current["edges"].append(line.strip())
            principals.update(principals_in(line))
        elif NO_ESCALATE_RE.search(line):
            principals.update(principals_in(line))
    if current:
        units.append(current)
    out = []
    for i, u in enumerate(units, 1):
        out.append({
            "id": "pmapper-%04d" % i,
            "title": "privesc: %s -> %s via %s" % (u["src"], u["dst"], guess_method(u["edges"])),
            "targets": [arnify(u["src"], account), arnify(u["dst"], account)],
            "hints": {
                "method": guess_method(u["edges"]),
                "edges": u["edges"],
                "account": account or "",
                "source": "pmapper preset privesc",
            },
        })
    return out, principals


def parse_json(data, account):
    """Parse analysis --output-type json ({'findings': [...]}) or a query JSON list."""
    units, principals = [], set()
    findings = []
    if isinstance(data, dict):
        findings = data.get("findings") or data.get("results") or []
    elif isinstance(data, list):
        findings = data
    i = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        desc = f.get("description") or f.get("reason") or json.dumps(f)
        title = f.get("title") or "pmapper finding"
        ps = principals_in(desc) + principals_in(title)
        principals.update(ps)
        edges = [l.strip() for l in desc.splitlines() if l.strip()]
        i += 1
        units.append({
            "id": "pmapper-%04d" % i,
            "title": title[:200],
            "targets": [arnify(p, account) for p in (ps[:2] if ps else [])],
            "hints": {
                "method": guess_method(edges),
                "edges": edges,
                "severity": str(f.get("severity", "")),
                "impact": str(f.get("impact", "")),
                "account": account or "",
                "source": "pmapper analysis",
            },
        })
    return units, principals


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--profile", help="AWS profile; runs `pmapper query \"preset privesc *\"`")
    src.add_argument("--input", help="pre-captured pmapper output (text or JSON) to parse instead")
    ap.add_argument("--account", help="12-digit account id (expands user/x -> full ARN; "
                                      "also selects the stored graph when no --profile)")
    ap.add_argument("-o", "--output", default="out/work-units.json",
                    help="work-units JSON array (default: %(default)s)")
    ap.add_argument("--assets", default="out/assets.json",
                    help="principal asset list (default: %(default)s)")
    args = ap.parse_args()

    if args.input:
        with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    else:
        raw = run_pmapper(args.profile, args.account)

    stripped = raw.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            units, principals = parse_json(json.loads(stripped), args.account)
        except json.JSONDecodeError:
            units, principals = parse_text(raw, args.account)
    else:
        units, principals = parse_text(raw, args.account)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(units, fh, indent=2)

    assets = [{"asset": arnify(p, args.account), "kind": "principal",
               "attrs": {"source": "pmapper"}} for p in sorted(principals)]
    os.makedirs(os.path.dirname(args.assets) or ".", exist_ok=True)
    with open(args.assets, "w", encoding="utf-8") as fh:
        json.dump(assets, fh, indent=2)

    sys.stderr.write("[+] %d work units -> %s | %d principals -> %s\n"
                     % (len(units), args.output, len(assets), args.assets))


if __name__ == "__main__":
    main()
