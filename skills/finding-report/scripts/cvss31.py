#!/usr/bin/env python3
"""CVSS v3.1 base-score calculator (official FIRST CVSS v3.1 specification).

Score a vector:
    python3 scripts/cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    echo 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N' | python3 scripts/cvss31.py

Build a vector from metric choices, then score it:
    python3 scripts/cvss31.py --build AV=N AC=L PR=N UI=N S=U C=H I=H A=H

Output (tab-separated):  <base score>  <SEVERITY>  <canonical vector>
Exit non-zero on an invalid vector or metric set.

The eight base metrics and their values:
    AV: N(etwork) A(djacent) L(ocal) P(hysical)
    AC: L(ow) H(igh)
    PR: N(one) L(ow) H(igh)
    UI: N(one) R(equired)
    S:  U(nchanged) C(hanged)
    C/I/A: H(igh) L(ow) N(one)
"""

import math
import sys

# Exact metric weights from the FIRST CVSS v3.1 specification (Table 8).
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    # PR weight depends on Scope: (Scope Unchanged, Scope Changed).
    "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},  # Scope has no weight; it switches formulas.
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}

METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

SEVERITY_BANDS = [
    (0.0, 0.0, "NONE"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
]


def roundup(value):
    """Roundup() exactly as defined in CVSS v3.1 Appendix A (integer-safe)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity(score):
    for lo, hi, name in SEVERITY_BANDS:
        if lo <= score <= hi:
            return name
    return "UNDEFINED"


def parse_vector(vector):
    """Parse a CVSS:3.1 (or 3.0) base vector string into a metric dict."""
    vector = vector.strip()
    parts = vector.split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise ValueError("vector must start with 'CVSS:3.1/' (got %r)" % vector[:16])
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError("malformed metric %r" % part)
        key, _, val = part.partition(":")
        key, val = key.upper(), val.upper()
        if key in metrics:
            raise ValueError("duplicate metric %r" % key)
        metrics[key] = val
    return validate_metrics(metrics)


def validate_metrics(metrics):
    errors = []
    for name in METRIC_ORDER:
        val = metrics.get(name)
        if val is None:
            errors.append("missing base metric %s (one of %s)"
                          % (name, "/".join(WEIGHTS[name])))
        elif val not in WEIGHTS[name]:
            errors.append("invalid value %s:%s (allowed: %s)"
                          % (name, val, "/".join(WEIGHTS[name])))
    # Temporal/environmental metrics are tolerated but ignored for base score.
    if errors:
        raise ValueError("; ".join(errors))
    return {name: metrics[name] for name in METRIC_ORDER}


def canonical_vector(metrics):
    return "CVSS:3.1/" + "/".join("%s:%s" % (m, metrics[m]) for m in METRIC_ORDER)


def base_score(metrics):
    """Base score per CVSS v3.1 spec section 7.1."""
    scope_changed = metrics["S"] == "C"
    c = WEIGHTS["C"][metrics["C"]]
    i = WEIGHTS["I"][metrics["I"]]
    a = WEIGHTS["A"][metrics["A"]]

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = WEIGHTS["PR"][metrics["PR"]][1 if scope_changed else 0]
    exploitability = (8.22 * WEIGHTS["AV"][metrics["AV"]]
                      * WEIGHTS["AC"][metrics["AC"]]
                      * pr
                      * WEIGHTS["UI"][metrics["UI"]])

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def build_from_choices(choices):
    """Build a metric dict from KEY=VALUE (or KEY:VALUE) arguments."""
    metrics = {}
    for choice in choices:
        sep = "=" if "=" in choice else ":"
        if sep not in choice:
            raise ValueError("expected METRIC=VALUE, got %r" % choice)
        key, _, val = choice.partition(sep)
        metrics[key.strip().upper()] = val.strip().upper()
    return validate_metrics(metrics)


def main(argv):
    args = argv[1:]
    try:
        if args and args[0] in ("-h", "--help"):
            print(__doc__)
            return 0
        if args and args[0] == "--build":
            if len(args) < 2:
                raise ValueError("--build needs AV= AC= PR= UI= S= C= I= A=")
            metrics = build_from_choices(args[1:])
        elif args:
            metrics = parse_vector(" ".join(args))
        else:
            data = sys.stdin.read().strip()
            if not data:
                raise ValueError("no vector on argv or stdin")
            metrics = parse_vector(data)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    score = base_score(metrics)
    print("%.1f\t%s\t%s" % (score, severity(score), canonical_vector(metrics)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
