#!/usr/bin/env python3
"""Pre-flight validator for a rupu finding `report` object (full profile).

Checks the report against the required-field, enum and sentinel rules of
urn:rupu:schema:finding-report:v1 BEFORE it is sent to findings.report, and
prints every problem at once with its field path (mirroring how rupu rejects),
so one fix pass suffices. Exit status: 0 clean, 1 problems found, 2 bad input.

Usage:
    python3 scripts/check_report.py report.json
    cat report.json | python3 scripts/check_report.py

Accepts either the bare report object or a whole findings.report call
({"report": {...}, "asset": {...}, "tags": [...]}) — the report inside is
validated. Keep the embedded rules in step with `rupu findings schema`.
"""

import json
import re
import sys

EM_DASH_SENTINEL = re.compile(r"^Not Provided \u2014 \S")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
CVSS_VECTOR_RE = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]"
)
SCORE_RE = re.compile(r"(?<![\d.])(10(\.0)?|[0-9](\.[0-9])?)(?![\d.])")

REQUIRED_KEYS = [
    "title", "ownership", "tickets", "rating", "category", "attack_vector",
    "cwe", "description", "impact", "location", "root_cause", "call_chain",
    "evidence", "remediation", "recommended_patch", "ci_cd_detection",
    "regression_test", "replication_steps", "cross_references", "references",
]
OPTIONAL_KEYS = ["artifacts", "blocks", "classifications"]
AGENT_MUST_OMIT = ["verification"]

RATING_4 = ["Low", "Medium", "High", "Critical"]
RATING_3 = ["Low", "Medium", "High"]
CALL_CHAIN_ROLES = ["source", "hop", "sink"]
XREF_RELATIONS = ["duplicate", "sibling", "prerequisite", "supersedes"]
BLOCK_KINDS = ["text", "code_slice", "diff", "table", "image", "hexdump",
               "disasm", "decompile", "http_exchange", "scan_output", "pcap_ref"]

problems = []


def problem(path, msg):
    problems.append("report.%s: %s" % (path, msg) if path else "report: %s" % msg)


def nonempty_str(value, path):
    if not isinstance(value, str):
        problem(path, "must be a string (got %s)" % type(value).__name__)
        return False
    if not value.strip():
        problem(path, "must be non-empty after trimming")
        return False
    return True


def check_lines(value, path):
    if value is None:
        return
    if (not isinstance(value, list) or len(value) != 2
            or not all(isinstance(n, int) for n in value)):
        problem(path, "must be [start, end] with two integers")
    elif not (1 <= value[0] <= value[1]):
        problem(path, "requires 1 <= start <= end (got %r)" % (value,))


def check_ownership(o):
    if not isinstance(o, dict):
        problem("ownership", "must be an object")
        return
    for key in ("owner", "product", "affected_component", "source_repository"):
        if key not in o:
            problem("ownership.%s" % key, "required")
        else:
            nonempty_str(o[key], "ownership.%s" % key)
    for key in o:
        if key not in ("owner", "product", "affected_component", "source_repository"):
            problem("ownership.%s" % key, "unknown key")


def check_tickets(t):
    if isinstance(t, str):
        if t not in ("None Provided", "Unknown"):
            problem("tickets", "string form must be exactly 'None Provided' or "
                               "'Unknown' (got %r)" % t)
        return
    if not isinstance(t, list) or not t:
        problem("tickets", "must be 'None Provided', 'Unknown', or a non-empty array")
        return
    for i, tk in enumerate(t):
        if not isinstance(tk, dict):
            problem("tickets[%d]" % i, "must be an object")
            continue
        for key in ("type", "identifier"):
            if key not in tk:
                problem("tickets[%d].%s" % (i, key), "required")
            else:
                nonempty_str(tk[key], "tickets[%d].%s" % (i, key))
        for key in tk:
            if key not in ("type", "identifier", "url", "notes"):
                problem("tickets[%d].%s" % (i, key), "unknown key")


def check_rating(r):
    if not isinstance(r, dict):
        problem("rating", "must be an object")
        return
    for key, allowed in (("impact", RATING_4), ("likelihood", RATING_3),
                         ("risk_rating", RATING_4), ("risk_factor", RATING_4)):
        if key not in r:
            problem("rating.%s" % key, "required")
        elif r[key] not in allowed:
            problem("rating.%s" % key, "must be one of %s (got %r)"
                    % ("/".join(allowed), r.get(key)))
    cv = r.get("cvss_v3")
    if cv is None:
        problem("rating.cvss_v3", "required ('Unknown' if it cannot be assessed)")
    elif nonempty_str(cv, "rating.cvss_v3") and cv != "Unknown":
        has_vector = CVSS_VECTOR_RE.search(cv)
        has_score = SCORE_RE.search(cv)
        if "CVSS" in cv.upper() and not has_vector:
            problem("rating.cvss_v3", "contains 'CVSS' but no valid full "
                    "CVSS:3.1 base vector (expected CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_)")
        elif not has_vector and not has_score:
            problem("rating.cvss_v3", "must be a base score (0.0-10.0), ideally "
                    "with the CVSS:3.1 vector, or exactly 'Unknown' — never a guess")


def check_call_chain(cc):
    if isinstance(cc, str):
        if not EM_DASH_SENTINEL.match(cc):
            problem("call_chain", "string form must match 'Not Provided \u2014 "
                    "<justification>' (em dash U+2014, non-empty justification)")
        return
    if not isinstance(cc, list) or not cc:
        problem("call_chain", "must be a non-empty array of hops or the "
                "'Not Provided \u2014 <justification>' sentinel")
        return
    for i, hop in enumerate(cc):
        p = "call_chain[%d]" % i
        if not isinstance(hop, dict):
            problem(p, "must be an object")
            continue
        if "label" not in hop:
            problem(p + ".label", "required")
        else:
            nonempty_str(hop["label"], p + ".label")
        if hop.get("role") not in CALL_CHAIN_ROLES:
            problem(p + ".role", "must be one of %s" % "/".join(CALL_CHAIN_ROLES))
        check_lines(hop.get("lines"), p + ".lines")
        for key in hop:
            if key not in ("label", "role", "file", "lines", "gate",
                           "passes_because", "binary_va"):
                problem(p + ".%s" % key, "unknown key")


def check_evidence(ev):
    if not isinstance(ev, list) or not ev:
        problem("evidence", "must be a non-empty array (at least one claim)")
        return
    for i, e in enumerate(ev):
        p = "evidence[%d]" % i
        if not isinstance(e, dict):
            problem(p, "must be an object")
            continue
        if "claim" not in e:
            problem(p + ".claim", "required")
        else:
            nonempty_str(e["claim"], p + ".claim")
        if "sha256" in e:
            problem(p + ".sha256", "set by rupu at write time — omit it")
        check_lines(e.get("lines"), p + ".lines")
        for key in e:
            if key not in ("claim", "file", "lines", "excerpt", "lang",
                           "artifact", "binary_va", "sha256"):
                problem(p + ".%s" % key, "unknown key")


def check_structured_or_sentinel(value, path, required_keys, optional_keys):
    if isinstance(value, str):
        if value == "Unknown":
            problem(path, "'Unknown' is not accepted here — provide the item or "
                          "'Not Provided \u2014 <justification>'")
        elif not EM_DASH_SENTINEL.match(value):
            problem(path, "string form must match 'Not Provided \u2014 "
                          "<justification>' (em dash U+2014)")
        return
    if not isinstance(value, dict):
        problem(path, "must be an object or the 'Not Provided \u2014 "
                      "<justification>' sentinel")
        return
    for key in required_keys:
        if key not in value:
            problem("%s.%s" % (path, key), "required")
        else:
            nonempty_str(value[key], "%s.%s" % (path, key))
    for key in value:
        if key not in required_keys and key not in optional_keys:
            problem("%s.%s" % (path, key), "unknown key")


def check_cross_references(xr):
    if isinstance(xr, str):
        if xr != "None":
            problem("cross_references", "string form must be exactly 'None'")
        return
    if not isinstance(xr, list) or not xr:
        problem("cross_references", "must be 'None' or a non-empty array")
        return
    for i, x in enumerate(xr):
        p = "cross_references[%d]" % i
        if not isinstance(x, dict):
            problem(p, "must be an object")
            continue
        if "finding_id" not in x:
            problem(p + ".finding_id", "required (the fnd_ id a previous "
                                       "findings.report call returned)")
        else:
            nonempty_str(x["finding_id"], p + ".finding_id")
        if x.get("relation") not in XREF_RELATIONS:
            problem(p + ".relation", "must be one of %s" % "/".join(XREF_RELATIONS))
        for key in x:
            if key not in ("finding_id", "relation", "note"):
                problem(p + ".%s" % key, "unknown key")


def check_optionals(report):
    for i, a in enumerate(report.get("artifacts") or []):
        p = "artifacts[%d]" % i
        if not isinstance(a, dict):
            problem(p, "must be an object")
            continue
        if "path" not in a:
            problem(p + ".path", "required (workspace-relative)")
        else:
            nonempty_str(a["path"], p + ".path")
        for key in ("sha256", "size", "kind", "stored", "host"):
            if key in a:
                problem(p + ".%s" % key, "filled by rupu when it stores the "
                                         "file — supply only 'path'")
    for i, b in enumerate(report.get("blocks") or []):
        p = "blocks[%d]" % i
        if not isinstance(b, dict):
            problem(p, "must be an object")
            continue
        if b.get("kind") not in BLOCK_KINDS:
            problem(p + ".kind", "must be one of %s" % ", ".join(BLOCK_KINDS))
        if b.get("kind") in ("image", "hexdump", "pcap_ref"):
            art = b.get("artifact")
            if not isinstance(art, dict) or not art.get("path"):
                problem(p + ".artifact.path", "an %s block names exactly one "
                        "file" % b.get("kind"))
    for i, c in enumerate(report.get("classifications") or []):
        p = "classifications[%d]" % i
        if not isinstance(c, dict):
            problem(p, "must be an object")
            continue
        for key in ("system", "id"):
            if key not in c:
                problem(p + ".%s" % key, "required")
            else:
                nonempty_str(c[key], p + ".%s" % key)
        for key in c:
            if key not in ("system", "id", "vector"):
                problem(p + ".%s" % key, "unknown key")


def check_report(report):
    for key in REQUIRED_KEYS:
        if key not in report:
            problem(key, "required field missing")
    for key in AGENT_MUST_OMIT:
        if key in report:
            problem(key, "set by verification runs, never by the reporting "
                         "agent — remove it")
    known = set(REQUIRED_KEYS) | set(OPTIONAL_KEYS) | set(AGENT_MUST_OMIT)
    for key in report:
        if key not in known:
            problem(key, "unknown key (schema has additionalProperties: false)")

    for key in ("title", "category", "attack_vector", "description", "impact",
                "root_cause", "remediation", "references"):
        if key in report:
            nonempty_str(report[key], key)

    if "ownership" in report:
        check_ownership(report["ownership"])
    if "tickets" in report:
        check_tickets(report["tickets"])
    if "rating" in report:
        check_rating(report["rating"])

    cwe = report.get("cwe")
    if cwe is not None:
        if not isinstance(cwe, list):
            problem("cwe", "must be an array of 'CWE-<n>' ids (may be empty)")
        else:
            for i, c in enumerate(cwe):
                if not isinstance(c, str) or not CWE_RE.match(c):
                    problem("cwe[%d]" % i, "must match ^CWE-[0-9]+$ (got %r)" % (c,))

    loc = report.get("location")
    if loc is not None:
        if not isinstance(loc, dict):
            problem("location", "must be an object with 'input' and 'output'")
        else:
            for key in ("input", "output"):
                if key not in loc:
                    problem("location.%s" % key, "required")
                else:
                    nonempty_str(loc[key], "location.%s" % key)
            for key in loc:
                if key not in ("input", "output"):
                    problem("location.%s" % key, "unknown key")

    if "call_chain" in report:
        check_call_chain(report["call_chain"])
    if "evidence" in report:
        check_evidence(report["evidence"])
    if "recommended_patch" in report:
        check_structured_or_sentinel(report["recommended_patch"],
                                     "recommended_patch", ["diff"], ["notes"])
    if "ci_cd_detection" in report:
        check_structured_or_sentinel(report["ci_cd_detection"], "ci_cd_detection",
                                     ["stage", "body", "expect"], ["command"])
    if "regression_test" in report:
        check_structured_or_sentinel(report["regression_test"], "regression_test",
                                     ["body", "command", "expect_vulnerable",
                                      "expect_patched"], [])

    steps = report.get("replication_steps")
    if steps is not None:
        if not isinstance(steps, list) or not steps:
            problem("replication_steps", "must be a non-empty array of steps")
        else:
            for i, s in enumerate(steps):
                nonempty_str(s, "replication_steps[%d]" % i)

    if "cross_references" in report:
        check_cross_references(report["cross_references"])
    check_optionals(report)


def main(argv):
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    try:
        raw = open(argv[1], "r", encoding="utf-8").read() if len(argv) > 1 \
            else sys.stdin.read()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        print("error: cannot read/parse input: %s" % exc, file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("error: top-level JSON must be an object", file=sys.stderr)
        return 2
    # Accept a whole findings.report call wrapper.
    report = data["report"] if isinstance(data.get("report"), dict) else data
    check_report(report)
    if problems:
        for p in problems:
            print(p)
        print("\n%d problem(s) — fix all, then re-run before calling "
              "findings.report." % len(problems))
        return 1
    print("OK: report passes pre-flight checks (full profile).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
