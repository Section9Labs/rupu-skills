#!/usr/bin/env python3
"""trace_context.py - print context + enclosing function for a file:line sink hit.

Speeds up manual back-tracing from a candidate sink: shows N lines of
surrounding context with line numbers, the target line marked '>', and the
enclosing function (signature, or the whole body with --function).

Usage:
  python3 scripts/trace_context.py app/views.py:42
  python3 scripts/trace_context.py app/views.py:42 lib/db.py:17 -n 20
  python3 scripts/trace_context.py app/views.py:42 --function
"""
import argparse
import os
import re
import sys

# (extensions, regex matching a function/method definition line)
DEF_PATTERNS = [
    ((".py",), re.compile(r"^(\s*)(async\s+)?def\s+\w+")),
    ((".rb",), re.compile(r"^(\s*)def\s+\S")),
    ((".go",), re.compile(r"^(func\s)")),
    ((".php",), re.compile(r"^(\s*)(public\s+|private\s+|protected\s+|static\s+)*function\s+\w+")),
    ((".java", ".kt", ".kts", ".scala", ".cs", ".groovy"),
     re.compile(r"^(\s*)(public|private|protected|internal|static|final|synchronized|override|abstract|fun|def)\b.*\(")),
    ((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
     re.compile(r"^(\s*)((export\s+)?(default\s+)?(async\s+)?function\b"
                r"|[\w$.\[\]'\"]+\s*[:=]\s*(async\s*)?(function\b|\()"
                r"|(public|private|protected|static|async)\s+[\w$]+\s*\("
                r"|[\w$]+\s*\([^;]*\)\s*\{)")),
]
BRACE_LANGS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt",
               ".kts", ".scala", ".cs", ".groovy", ".go", ".php", ".c", ".cc",
               ".cpp", ".h", ".hpp", ".rs")
INDENT_LANGS = (".py",)


def def_regex_for(path):
    ext = os.path.splitext(path)[1].lower()
    for exts, rx in DEF_PATTERNS:
        if ext in exts:
            return rx
    # generic fallback: looks-like-a-definition
    return re.compile(r"^(\s*)\w[\w\s*&<>\[\],.$]*\(")


def indent_of(line):
    return len(line) - len(line.lstrip(" \t"))


def find_enclosing(lines, target_idx, rx):
    """Scan upward from target for the nearest definition line. Returns index or None."""
    tgt_indent = indent_of(lines[target_idx]) if lines[target_idx].strip() else 10 ** 6
    for i in range(target_idx, -1, -1):
        line = lines[i]
        if not line.strip():
            continue
        if rx.match(line):
            # for indent-based langs, def must be shallower than the target
            if i == target_idx or indent_of(line) <= tgt_indent:
                return i
    return None


def function_end(lines, def_idx, path):
    """Heuristic end-of-function line index (inclusive)."""
    ext = os.path.splitext(path)[1].lower()
    n = len(lines)
    cap = min(n - 1, def_idx + 400)
    if ext in INDENT_LANGS or ext == ".rb" and "end" not in "".join(lines[def_idx:def_idx + 2]):
        base = indent_of(lines[def_idx])
        last = def_idx
        for i in range(def_idx + 1, cap + 1):
            if not lines[i].strip():
                continue
            if indent_of(lines[i]) <= base:
                break
            last = i
        return last
    if ext == ".rb":
        base = indent_of(lines[def_idx])
        for i in range(def_idx + 1, cap + 1):
            if lines[i].strip() == "end" and indent_of(lines[i]) <= base:
                return i
        return cap
    # brace counting
    depth = 0
    seen_open = False
    for i in range(def_idx, cap + 1):
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            seen_open = True
        if seen_open and depth <= 0:
            return i
    return cap


def render(path, lineno, ctx, whole_function):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if not 1 <= lineno <= len(lines):
        print("error: %s has %d lines, no line %d" % (path, len(lines), lineno), file=sys.stderr)
        return 1
    idx = lineno - 1
    rx = def_regex_for(path)
    def_idx = find_enclosing(lines, idx, rx)

    if def_idx is not None:
        encl = "%s @ line %d" % (lines[def_idx].strip()[:100], def_idx + 1)
    else:
        encl = "<module scope>"
    print("== %s:%d  (enclosing: %s) ==" % (path, lineno, encl))

    if whole_function and def_idx is not None:
        start = def_idx
        end = max(function_end(lines, def_idx, path), idx)
    else:
        start = max(0, idx - ctx)
        end = min(len(lines) - 1, idx + ctx)
        if def_idx is not None and def_idx < start:
            print("  %5d | %s" % (def_idx + 1, lines[def_idx]))
            print("    ... |")
    for i in range(start, end + 1):
        marker = ">" if i == idx else " "
        print("%s %5d | %s" % (marker, i + 1, lines[i]))
    print()
    return 0


def parse_target(spec):
    if ":" not in spec:
        raise ValueError("expected path:line, got %r" % spec)
    path, _, ln = spec.rpartition(":")
    return path, int(ln)


def main():
    ap = argparse.ArgumentParser(description="Print context + enclosing function for file:line targets.")
    ap.add_argument("targets", nargs="+", help="one or more path:line specs (as emitted by sink_hunt.py)")
    ap.add_argument("-n", "--context", type=int, default=12, help="context lines before/after (default 12)")
    ap.add_argument("--function", action="store_true", help="print the whole enclosing function instead of a window")
    args = ap.parse_args()

    rc = 0
    for spec in args.targets:
        try:
            path, lineno = parse_target(spec)
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            rc = 1
            continue
        rc |= render(path, lineno, args.context, args.function)
    return rc


if __name__ == "__main__":
    sys.exit(main())
