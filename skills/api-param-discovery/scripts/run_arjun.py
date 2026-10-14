#!/usr/bin/env python3
"""run_arjun.py - drive arjun over an endpoint list across method types.

Reads either a flat endpoint file (one URL per line) or the normalized
request set emitted by api-spec-discovery (JSON list of operations, or
{"operations": [...]}), runs arjun once per (url, method) with the given
auth headers and tuning flags, captures each -oJ output, and writes one
combined, deduplicated results file atomically.

Examples:
    python3 scripts/run_arjun.py \
        --request-set reports/api-spec-requestset.json \
        --methods GET,POST,JSON \
        --headers "Authorization: Bearer eyJ..." \
        --ratelimit 20 \
        -o reports/arjun-results.json

    python3 scripts/run_arjun.py --endpoints reports/endpoints.txt \
        --methods GET --wordlist large -o reports/arjun-results.json

Output shape (consumed by merge_params.py):
    {"generated": "...", "results": [
        {"url": "...", "method": "GET", "params": ["debug", ...],
         "arjun_exit": 0}, ...]}

Stdlib only.
"""

import argparse
import datetime
import json
import os
import shlex
import subprocess
import sys
import tempfile

VALID_METHODS = ("GET", "POST", "JSON", "XML")


def atomic_write_json(path, obj):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".arjun-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_targets(args):
    """Return list of (url, methods) tuples."""
    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    for m in methods:
        if m not in VALID_METHODS:
            sys.exit("invalid method %r (choose from %s)" % (m, "/".join(VALID_METHODS)))

    targets = []
    seen = set()

    if args.request_set:
        with open(args.request_set, encoding="utf-8") as fh:
            data = json.load(fh)
        ops = data.get("operations", data) if isinstance(data, dict) else data
        if not isinstance(ops, list):
            sys.exit("unrecognized request-set shape in %s" % args.request_set)
        for op in ops:
            if not isinstance(op, dict):
                continue
            url = op.get("url")
            if not url:
                base = (op.get("base_url") or "").rstrip("/")
                path = op.get("path") or ""
                if base and path:
                    url = base + "/" + path.lstrip("/")
            if not url:
                continue
            op_method = (op.get("method") or "").upper()
            # Map HTTP verbs onto arjun method types; always include the
            # requested sweep methods so cross-source params are found too.
            use = list(methods)
            if op_method == "GET" and "GET" not in use:
                use.append("GET")
            if op_method in ("POST", "PUT", "PATCH") and "JSON" not in use:
                use.append("JSON")
            key = (url, tuple(sorted(use)))
            if key not in seen:
                seen.add(key)
                targets.append((url, use))

    if args.endpoints:
        with open(args.endpoints, encoding="utf-8") as fh:
            for line in fh:
                url = line.strip()
                if not url or url.startswith("#"):
                    continue
                key = (url, tuple(sorted(methods)))
                if key not in seen:
                    seen.add(key)
                    targets.append((url, list(methods)))

    if not targets:
        sys.exit("no targets: pass --request-set and/or --endpoints")
    return targets


def read_headers(value):
    """--headers accepts a literal string or @file; normalize \\n escapes."""
    if value is None:
        return None
    if value.startswith("@"):
        with open(value[1:], encoding="utf-8") as fh:
            value = fh.read().strip()
    return value.replace("\\n", "\n")


def build_cmd(args, url, method, out_json):
    cmd = [args.arjun_bin, "-u", url, "-m", method, "-oJ", out_json, "-q"]
    if args.wordlist:
        cmd += ["-w", args.wordlist]
    if args.headers_str:
        cmd += ["--headers", args.headers_str]
    if args.include:
        cmd += ["--include", args.include]
    if args.chunk:
        cmd += ["-c", str(args.chunk)]
    if args.threads:
        cmd += ["-t", str(args.threads)]
    if args.timeout:
        cmd += ["-T", str(args.timeout)]
    if args.delay:
        cmd += ["-d", str(args.delay)]
    if args.ratelimit:
        cmd += ["--ratelimit", str(args.ratelimit)]
    if args.stable:
        cmd += ["--stable"]
    if args.disable_redirects:
        cmd += ["--disable-redirects"]
    if args.casing:
        cmd += ["--casing"]
    if args.extra:
        cmd += shlex.split(args.extra)
    return cmd


def parse_arjun_json(path, want_url):
    """Handle both modern ({url: {params: [...]}}) and legacy ({url: [...]})
    arjun -oJ shapes. Returns a list of param names."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    # Prefer the exact URL key; fall back to the single key if there is one.
    entry = data.get(want_url)
    if entry is None and len(data) == 1:
        entry = next(iter(data.values()))
    if entry is None:
        return []
    if isinstance(entry, list):
        return [str(p) for p in entry]
    if isinstance(entry, dict):
        params = entry.get("params", [])
        if isinstance(params, list):
            return [str(p) for p in params]
    return []


def main():
    ap = argparse.ArgumentParser(description="Run arjun across endpoints/methods.")
    src = ap.add_argument_group("targets")
    src.add_argument("--request-set", help="api-spec-discovery normalized request set (JSON)")
    src.add_argument("--endpoints", help="flat file: one URL per line")
    ap.add_argument("--methods", default="GET,POST,JSON",
                    help="comma-separated arjun method types to sweep (default GET,POST,JSON)")
    ap.add_argument("--headers", dest="headers", default=None,
                    help="headers string ('H1: v\\nH2: v') or @file")
    ap.add_argument("--include", default=None,
                    help="static data merged into every request, e.g. '{\"api_key\":\"x\"}'")
    ap.add_argument("--wordlist", "-w", default=None,
                    help="wordlist: small/medium/large or a file path (default: arjun default dict)")
    ap.add_argument("--chunk", "-c", type=int, default=None, help="params per request (arjun -c)")
    ap.add_argument("--threads", "-t", type=int, default=None, help="threads (arjun -t)")
    ap.add_argument("--timeout", "-T", type=int, default=None, help="request timeout (arjun -T)")
    ap.add_argument("--delay", "-d", type=int, default=None, help="delay seconds (forces 1 thread)")
    ap.add_argument("--ratelimit", type=int, default=None, help="max requests/second")
    ap.add_argument("--stable", action="store_true", help="arjun --stable")
    ap.add_argument("--disable-redirects", action="store_true")
    ap.add_argument("--casing", action="store_true")
    ap.add_argument("--extra", default=None, help="extra raw arjun args, shell-quoted")
    ap.add_argument("--arjun-bin", default="arjun", help="arjun executable (default: arjun)")
    ap.add_argument("--run-timeout", type=int, default=3600,
                    help="kill a single arjun run after N seconds (default 3600)")
    ap.add_argument("-o", "--output", required=True, help="combined results JSON path")
    args = ap.parse_args()

    args.headers_str = read_headers(args.headers)
    targets = load_targets(args)

    results = []
    total = sum(len(ms) for _, ms in targets)
    done = 0
    with tempfile.TemporaryDirectory(prefix="arjun-runs-") as tmpdir:
        for url, methods in targets:
            for method in methods:
                done += 1
                out_json = os.path.join(tmpdir, "run-%d.json" % done)
                cmd = build_cmd(args, url, method, out_json)
                print("[%d/%d] %s" % (done, total, " ".join(shlex.quote(c) for c in cmd)),
                      file=sys.stderr)
                try:
                    proc = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=args.run_timeout)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    print("  ! timed out", file=sys.stderr)
                    exit_code = -1
                except FileNotFoundError:
                    sys.exit("arjun not found (%r); pipx install arjun" % args.arjun_bin)
                params = parse_arjun_json(out_json, url)
                if params:
                    print("  + %d param(s): %s" % (len(params), ", ".join(sorted(params))),
                          file=sys.stderr)
                results.append({
                    "url": url,
                    "method": method,
                    "params": sorted(set(params)),
                    "arjun_exit": exit_code,
                })

    out = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": "arjun",
        "results": results,
    }
    atomic_write_json(args.output, out)
    found = sum(1 for r in results if r["params"])
    print("wrote %s (%d runs, %d with new params)" % (args.output, len(results), found),
          file=sys.stderr)


if __name__ == "__main__":
    main()
