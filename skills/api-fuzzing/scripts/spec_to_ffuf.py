#!/usr/bin/env python3
"""spec_to_ffuf.py — turn api-spec-discovery's normalized request set into ffuf tasks.

Reads a JSON request set (bare array, or {"operations":[...]}/{"requests":[...]})
and emits, under the output dir (default reports/ffuf/):

  manifest.json   JSON array of tasks: {task_id, op_id, kind, method, url, cmd, output}
  commands.sh     runnable shell script (one ffuf invocation per task)
  ids.txt         generated numeric/edge id wordlist (path-id, body-field int fuzz)
  values.txt      type-boundary value probes (param-value, body-field)
  methods.txt     HTTP verbs for method tampering

Usage:
  python3 scripts/spec_to_ffuf.py reports/api-requests.json \
      -o reports/ffuf --base https://api.example.com \
      --header 'Authorization: Bearer eyJ...' --proxy http://127.0.0.1:8080 \
      --param-wordlist /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
      --path-wordlist /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
      --rate 100 --threads 40

Only python3 stdlib. Writes manifest.json atomically.
"""

import argparse
import copy
import json
import os
import re
import shlex
import sys
import tempfile

PLACEHOLDER_RE = re.compile(r"\{([^{}/]+)\}")

ID_WORDS = [str(n) for n in range(0, 101)] + [
    "1000", "9999", "123456", "-1", "0001", "4294967296", "%00", "null", "true",
]

VALUE_WORDS = [
    "0", "-1", "1", "9999999999", "null", "true", "false",
    '""', '"*"', '"\'"', '"%27"', '"../"', '"../../etc/passwd"',
    '"{{7*7}}"', '"${7*7}"', '"<x>"', '"\\u0000"', "[1]", '{"$gt":""}',
]

METHOD_WORDS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "FOO"]

BODY_SENTINEL = "__FFUF_FUZZ_SENTINEL__"


def atomic_write(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_ops(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict):
        for key in ("operations", "requests", "ops"):
            if isinstance(doc.get(key), list):
                return doc[key]
        raise SystemExit("error: no operations/requests array in %s" % path)
    if isinstance(doc, list):
        return doc
    raise SystemExit("error: unexpected JSON top-level type in %s" % path)


def op_url(op, base):
    url = op.get("url") or op.get("path") or ""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if not base:
        return None
    return base.rstrip("/") + "/" + url.lstrip("/")


def param_example(param):
    if isinstance(param, dict):
        ex = param.get("example")
        if ex is not None:
            return str(ex)
        t = (param.get("type") or "").lower()
        if t in ("integer", "number", "int"):
            return "1"
        if t == "boolean":
            return "true"
        return "x"
    return "1"


def pin_placeholders(url, params, fuzz_name=None):
    """Replace {name} placeholders: fuzz_name -> FUZZ, others -> example values."""
    by_name = {}
    for p in params or []:
        name = p.get("name") if isinstance(p, dict) else None
        if name:
            by_name[name] = p

    def repl(m):
        name = m.group(1)
        if fuzz_name is not None and name == fuzz_name:
            return "FUZZ"
        return param_example(by_name.get(name, {}))

    return PLACEHOLDER_RE.sub(repl, url)


def body_leaves(body):
    """Return [(dotted_path, template_json_string_with_raw_FUZZ)] for scalar leaves."""
    leaves = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, path + [i])
        else:
            leaves.append(list(path))

    walk(body, [])
    out = []
    for leaf in leaves:
        b = copy.deepcopy(body)
        cur = b
        for key in leaf[:-1]:
            cur = cur[key]
        cur[leaf[-1]] = BODY_SENTINEL
        tmpl = json.dumps(b).replace(json.dumps(BODY_SENTINEL), "FUZZ")
        out.append((".".join(str(k) for k in leaf), tmpl))
    return out


def base_dirs(url):
    """Directory bases of a URL for path-segment fuzzing (placeholders stripped)."""
    m = re.match(r"^(https?://[^/]+)(/.*)?$", url)
    if not m:
        return []
    host, path = m.group(1), m.group(2) or "/"
    # cut at first placeholder
    path = path.split("{", 1)[0]
    segs = [s for s in path.split("/") if s]
    bases = [host + "/"]
    acc = ""
    for s in segs[:-1] if segs else []:
        acc += "/" + s
        bases.append(host + acc + "/")
    return bases


class TaskBuilder(object):
    def __init__(self, args):
        self.args = args
        self.tasks = []
        self.n = 0

    def common_flags(self, fc):
        a = self.args
        flags = ["-mc", "all", "-fc", fc, "-ac",
                 "-t", str(a.threads), "-timeout", str(a.timeout)]
        if a.rate:
            flags += ["-rate", str(a.rate)]
        if a.proxy:
            flags += ["-x", a.proxy]
        for h in a.header or []:
            flags += ["-H", h]
        return flags

    def add(self, kind, op_id, method, url, argv_extra, headers=None, fc="404"):
        self.n += 1
        task_id = "t%03d-%s" % (self.n, kind)
        out = os.path.join(self.args.out, "out", task_id + ".json")
        dump = os.path.join(self.args.out, "dump", task_id)
        argv = ["ffuf", "-u", url]
        if method and method.upper() != "GET":
            argv += ["-X", method.upper()]
        for k, v in (headers or {}).items():
            argv += ["-H", "%s: %s" % (k, v)]
        argv += argv_extra
        argv += self.common_flags(fc)
        argv += ["-o", out, "-of", "json", "-od", dump]
        cmd = " ".join(shlex.quote(a) for a in argv)
        self.tasks.append({
            "task_id": task_id, "op_id": op_id, "kind": kind,
            "method": (method or "GET").upper(), "url": url,
            "cmd": cmd, "output": out, "dump": dump,
        })


def main():
    ap = argparse.ArgumentParser(description="normalized request set -> ffuf tasks")
    ap.add_argument("requests", help="normalized request set JSON from api-spec-discovery")
    ap.add_argument("-o", "--out", default="reports/ffuf", help="output dir (default reports/ffuf)")
    ap.add_argument("--base", default=None, help="base URL for relative operation paths")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header for every request (repeatable), e.g. 'Authorization: Bearer ...'")
    ap.add_argument("--proxy", default=None, help="upstream proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--param-wordlist", default="burp-parameter-names.txt",
                    help="wordlist for param-name fuzzing")
    ap.add_argument("--path-wordlist", default="api-endpoints.txt",
                    help="wordlist for path-segment fuzzing")
    ap.add_argument("--id-wordlist", default=None,
                    help="wordlist for path-id / id value fuzzing (default: generated ids.txt)")
    ap.add_argument("--rate", type=int, default=0, help="ffuf -rate req/s (0 = unlimited)")
    ap.add_argument("--threads", type=int, default=40, help="ffuf -t threads")
    ap.add_argument("--timeout", type=int, default=10, help="ffuf -timeout seconds")
    ap.add_argument("--no-path-segment", action="store_true", help="skip route discovery tasks")
    ap.add_argument("--no-method", action="store_true", help="skip verb tampering tasks")
    args = ap.parse_args()

    ops = load_ops(args.requests)
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(os.path.join(args.out, "out"), exist_ok=True)

    ids_path = args.id_wordlist or os.path.join(args.out, "ids.txt")
    if not args.id_wordlist:
        atomic_write(ids_path, "\n".join(ID_WORDS) + "\n")
    values_path = os.path.join(args.out, "values.txt")
    atomic_write(values_path, "\n".join(VALUE_WORDS) + "\n")
    methods_path = os.path.join(args.out, "methods.txt")
    atomic_write(methods_path, "\n".join(METHOD_WORDS) + "\n")

    tb = TaskBuilder(args)
    seen_bases = set()
    seen_method_routes = set()

    for i, op in enumerate(ops):
        if not isinstance(op, dict):
            continue
        op_id = str(op.get("id") or op.get("operationId") or "op%03d" % i)
        method = str(op.get("method") or "GET").upper()
        url = op_url(op, args.base)
        if not url:
            sys.stderr.write("skip %s: relative url and no --base\n" % op_id)
            continue
        headers = dict(op.get("headers") or {})
        content_type = op.get("content_type") or headers.get("Content-Type")
        path_params = op.get("path_params") or []
        query_params = op.get("query_params") or []
        body = op.get("body")

        # --- path-segment: unique directory bases ---
        if not args.no_path_segment:
            for b in base_dirs(url):
                if b in seen_bases:
                    continue
                seen_bases.add(b)
                tb.add("path-segment", op_id, "GET", b + "FUZZ",
                       ["-w", args.path_wordlist + ":FUZZ",
                        "-recursion", "-recursion-depth", "2"])

        # --- path-id: each {param} in turn ---
        names_in_url = PLACEHOLDER_RE.findall(url)
        for name in names_in_url:
            fuzz_url = pin_placeholders(url, path_params, fuzz_name=name)
            tb.add("path-id", op_id, method, fuzz_url,
                   ["-w", ids_path + ":FUZZ"], headers=headers)

        pinned_url = pin_placeholders(url, path_params)

        # --- param-name: hidden query param discovery ---
        qs_fixed = "&".join(
            "%s=%s" % (p.get("name"), param_example(p))
            for p in query_params if isinstance(p, dict) and p.get("name"))
        sep = "&" if ("?" in pinned_url or qs_fixed) else "?"
        pn_url = pinned_url + ("?" + qs_fixed if qs_fixed and "?" not in pinned_url else "")
        tb.add("param-name", op_id, method, pn_url + sep + "FUZZ=1",
               ["-w", args.param_wordlist + ":FUZZ"], headers=headers)

        # --- param-value: each documented query param ---
        for p in query_params:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            parts = []
            for q in query_params:
                if not isinstance(q, dict) or not q.get("name"):
                    continue
                if q is p:
                    parts.append("%s=FUZZ" % q["name"])
                else:
                    parts.append("%s=%s" % (q["name"], param_example(q)))
            pv_url = pinned_url + ("&" if "?" in pinned_url else "?") + "&".join(parts)
            tb.add("param-value", op_id, method, pv_url,
                   ["-w", values_path + ":FUZZ"], headers=headers)

        # --- body-field: one JSON scalar leaf at a time ---
        if isinstance(body, (dict, list)) and body:
            hdrs = dict(headers)
            hdrs.setdefault("Content-Type", content_type or "application/json")
            for leaf, tmpl in body_leaves(body):
                tb.add("body-field", "%s[%s]" % (op_id, leaf), method, pinned_url,
                       ["-d", tmpl, "-w", values_path + ":FUZZ"], headers=hdrs)
            # body param-name: inject an undocumented key (key stays quoted so
            # ffuf's raw substitution yields valid JSON: "FUZZ":"1" -> "debug":"1")
            if isinstance(body, dict):
                injected = dict(body)
                injected["FUZZ"] = "1"
                tb.add("param-name", op_id + "[body]", method, pinned_url,
                       ["-d", json.dumps(injected),
                        "-w", args.param_wordlist + ":FUZZ"], headers=hdrs)

        # --- method tampering: once per unique pinned route ---
        # ffuf -fc is single-valued (last wins), so merge 404+405 here
        if not args.no_method and pinned_url not in seen_method_routes:
            seen_method_routes.add(pinned_url)
            tb.add("method", op_id, "FUZZ", pinned_url,
                   ["-w", methods_path + ":FUZZ"], headers=headers, fc="404,405")

    manifest_path = os.path.join(args.out, "manifest.json")
    atomic_write(manifest_path, json.dumps(tb.tasks, indent=2) + "\n")

    sh = ["#!/bin/sh", "set -u",
          "mkdir -p %s" % shlex.quote(os.path.join(args.out, "out")), ""]
    for t in tb.tasks:
        sh.append("# %s %s %s (%s)" % (t["task_id"], t["method"], t["url"], t["kind"]))
        sh.append("mkdir -p %s" % shlex.quote(t["dump"]))
        sh.append(t["cmd"])
        sh.append("")
    atomic_write(os.path.join(args.out, "commands.sh"), "\n".join(sh))

    kinds = {}
    for t in tb.tasks:
        kinds[t["kind"]] = kinds.get(t["kind"], 0) + 1
    sys.stderr.write("generated %d tasks from %d operations: %s\n"
                     % (len(tb.tasks), len(ops),
                        ", ".join("%s=%d" % kv for kv in sorted(kinds.items()))))
    print(manifest_path)


if __name__ == "__main__":
    main()
