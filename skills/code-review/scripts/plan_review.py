#!/usr/bin/env python3
"""plan_review.py — turn a repo profile into a CLEAN JSON array of work units.

Reads the repo-profile JSON produced by scripts/profile_repo.py and emits the
initial review plan: one work unit per tool-to-run (plus one per high-signal
entry-point cluster for the taint phase), written to a file as a top-level
JSON array so rupu's `read_file` + `for_each:` can consume it directly:

  [{"id": "...", "title": "...", "targets": ["path", ...],
    "hints": {"skill": "...", "phase": "...", "severity": "info", ...}}, ...]

Usage:
  python3 scripts/plan_review.py repo-profile.json -o plan.json
  python3 scripts/plan_review.py repo-profile.json          # stdout
"""
import argparse
import json
import sys

PHASE_OF = {
    "semgrep": "1-sast", "codeql": "1-sast", "bandit": "1-sast", "gosec": "1-sast",
    "brakeman": "1-sast", "njsscan": "1-sast", "find-sec-bugs": "1-sast",
    "gitleaks": "2-secrets", "trufflehog": "2-secrets",
    "grype-syft": "3-sca", "osv-scanner": "3-sca", "dependency-check": "3-sca",
    "retire-js": "3-sca", "cargo-audit": "3-sca",
    "taint-analysis": "4-taint",
}

TOOL_LANGS = {
    "bandit": {"python"}, "gosec": {"go"}, "brakeman": {"ruby"},
    "njsscan": {"javascript", "typescript"},
    "find-sec-bugs": {"java", "kotlin", "scala", "groovy"},
    "cargo-audit": {"rust"}, "retire-js": {"javascript", "typescript"},
}

TOOL_ECOS = {
    "osv-scanner": None,  # all manifests
    "grype-syft": None,
    "dependency-check": {"maven", "gradle", "nuget"},
    "cargo-audit": {"cargo"},
    "retire-js": {"npm"},
}


def build_plan(profile):
    repo = profile.get("repo", ".")
    langs = {l["lang"] for l in profile.get("languages", [])}
    manifests = profile.get("manifests", [])
    entry_points = profile.get("entry_points", [])
    tools = profile.get("suggested_tools", [])

    units = []
    seq = 0

    def unit(title, targets, hints):
        nonlocal seq
        seq += 1
        units.append({
            "id": f"cr-{seq:03d}",
            "title": title,
            "targets": targets or [repo],
            "hints": hints,
        })

    for tool in tools:
        phase = PHASE_OF.get(tool, "1-sast")
        hints = {"skill": tool, "phase": phase, "severity": "info", "repo": repo}

        if phase == "1-sast":
            tl = TOOL_LANGS.get(tool)
            tgt_langs = sorted(tl & langs) if tl else sorted(langs)
            hints["languages"] = ",".join(tgt_langs)
            unit(f"Run {tool} SAST over {repo}", [repo], hints)
        elif phase == "2-secrets":
            hints["scan"] = "worktree+history"
            unit(f"Run {tool} secret scan (worktree + full git history)", [repo], hints)
        elif phase == "3-sca":
            ecos = TOOL_ECOS.get(tool)
            targets = [m["path"] for m in manifests if ecos is None or m["ecosystem"] in ecos]
            if not targets and ecos is not None:
                continue  # ecosystem not present
            hints["manifests"] = ",".join(targets[:20])
            unit(f"Run {tool} dependency scan", targets or [repo], hints)
        elif phase == "4-taint":
            continue  # handled below as per-cluster units

    # taint units: cluster entry points by top reason
    clusters = {}
    for ep in entry_points:
        for reason in ep.get("reasons", []):
            clusters.setdefault(reason, []).append(ep["path"])
    priority = ["http-route", "deserialization", "command-exec", "raw-sql",
                "templating", "auth-logic", "possible-secret", "cli-main"]
    for reason in priority:
        paths = clusters.get(reason)
        if not paths:
            continue
        unit(
            f"Taint-trace {reason} entry points ({len(paths)} files)",
            sorted(set(paths)),
            {"skill": "taint-analysis", "phase": "4-taint",
             "severity": "info", "source_class": reason, "repo": repo},
        )

    return units


def main():
    ap = argparse.ArgumentParser(description="Emit the initial code-review work-unit plan from a repo profile.")
    ap.add_argument("profile", help="repo-profile.json from profile_repo.py")
    ap.add_argument("-o", "--output", help="write the JSON array here (default: stdout)")
    args = ap.parse_args()

    try:
        with open(args.profile, encoding="utf-8") as f:
            profile = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error reading profile: {e}", file=sys.stderr)
        sys.exit(2)

    units = build_plan(profile)
    out = json.dumps(units, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(f"wrote {args.output}: {len(units)} work units", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
