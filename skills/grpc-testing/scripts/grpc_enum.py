#!/usr/bin/env python3
"""grpc_enum.py - enumerate a gRPC server with grpcurl reflection (or protoset)
and emit a normalized method inventory plus a rupu work-unit array.

Usage:
  python3 scripts/grpc_enum.py 203.0.113.20:50051 --plaintext \
      -H "authorization: Bearer eyJ..." -o reports/grpc-203.0.113.20

Outputs (atomic writes):
  <prefix>-inventory.json   full inventory: services, methods, message schemas
  <prefix>-units.json       [{"id","title","targets","hints"}, ...] one per method

Python 3 standard library only. Requires grpcurl on PATH (or --grpcurl).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

MAX_TARGET_LEN = 200  # length-cap server-derived strings placed in units

RPC_RE = re.compile(
    r"rpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(stream\s+)?\.?([A-Za-z0-9_.]+)\s*\)"
    r"\s*returns\s*\(\s*(stream\s+)?\.?([A-Za-z0-9_.]+)\s*\)"
)
FIELD_RE = re.compile(
    r"^\s*(?:repeated\s+|optional\s+|required\s+)?\.?([A-Za-z0-9_.<>, ]+?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\d+", re.M
)

ID_FIELD_RE = re.compile(r"(^|_)(id|uid|uuid|guid|owner|account|tenant|user|org)($|_)", re.I)
PRIV_NAME_RE = re.compile(
    r"(admin|internal|delete|remove|purge|set|update|create|grant|revoke|"
    r"impersonate|sudo|debug|config|export|batch)", re.I
)
STRING_TYPES = ("string", "bytes")


def run_grpcurl(args, verb_args):
    cmd = [args.grpcurl]
    if args.plaintext:
        cmd.append("-plaintext")
    if args.insecure:
        cmd.append("-insecure")
    if args.authority:
        cmd += ["-authority", args.authority]
    cmd += ["-connect-timeout", str(args.connect_timeout),
            "-max-time", str(args.max_time)]
    for h in args.header:
        cmd += ["-H", h]
    for p in args.protoset:
        cmd += ["-protoset", p]
    for p in args.proto:
        cmd += ["-proto", p]
    for p in args.import_path:
        cmd += ["-import-path", p]
    cmd.append(args.target)
    cmd += verb_args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=args.max_time + args.connect_timeout + 5)
    except FileNotFoundError:
        sys.exit("error: grpcurl not found (install it or pass --grpcurl /path)")
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    return proc.returncode, proc.stdout, proc.stderr


def list_services(args):
    rc, out, err = run_grpcurl(args, ["list"])
    if rc != 0:
        sys.exit("error: 'grpcurl list' failed: %s" % err.strip())
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def describe(args, symbol):
    rc, out, err = run_grpcurl(args, ["describe", symbol])
    if rc != 0:
        print("warn: describe %s failed: %s" % (symbol, err.strip()),
              file=sys.stderr)
        return ""
    return out


def parse_methods(service, text):
    methods = []
    for m in RPC_RE.finditer(text):
        methods.append({
            "service": service,
            "method": m.group(1),
            "full": "%s/%s" % (service, m.group(1)),
            "input_type": m.group(3),
            "output_type": m.group(5),
            "client_streaming": bool(m.group(2)),
            "server_streaming": bool(m.group(4)),
        })
    return methods


def parse_fields(text):
    """Parse 'type name = N' lines from a describe of a message type."""
    fields = []
    for m in FIELD_RE.finditer(text):
        fields.append({"type": m.group(1).strip(), "name": m.group(2)})
    return fields


def hints_for(method, fields):
    """Fixed-vocabulary hints only; nothing server-derived."""
    hints = ["auth-metadata-matrix"]
    if PRIV_NAME_RE.search(method["method"]) or PRIV_NAME_RE.search(method["service"]):
        hints.append("bfla-privileged-name")
    if any(ID_FIELD_RE.search(f["name"]) for f in fields):
        hints.append("bola-id-fields")
    if any(f["type"] in STRING_TYPES for f in fields):
        hints.append("injection-string-fields")
    if method["client_streaming"] or method["server_streaming"]:
        hints.append("streaming")
    return hints


def cap(s):
    return s[:MAX_TARGET_LEN]


def atomic_write(path, obj):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print("wrote %s" % path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", help="host:port, e.g. 203.0.113.20:50051")
    ap.add_argument("--plaintext", action="store_true", help="h2c, no TLS")
    ap.add_argument("--insecure", action="store_true",
                    help="TLS, skip cert verification")
    ap.add_argument("--authority", default="", help=":authority override")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="metadata header 'name: value' (repeatable)")
    ap.add_argument("--protoset", action="append", default=[],
                    help="descriptor set file (when reflection is off)")
    ap.add_argument("--proto", action="append", default=[],
                    help=".proto file (repeatable)")
    ap.add_argument("--import-path", action="append", default=[],
                    help="proto import path (repeatable)")
    ap.add_argument("--connect-timeout", type=int, default=10)
    ap.add_argument("--max-time", type=int, default=20)
    ap.add_argument("--grpcurl", default="grpcurl", help="path to grpcurl")
    ap.add_argument("--no-messages", action="store_true",
                    help="skip describing input message types (fewer calls)")
    ap.add_argument("-o", "--output-prefix", default=None,
                    help="output prefix (default reports/grpc-<target>)")
    args = ap.parse_args()

    prefix = args.output_prefix or os.path.join(
        "reports", "grpc-" + re.sub(r"[^A-Za-z0-9._-]", "_", args.target))

    services = list_services(args)
    reflection = any(".reflection." in s for s in services)
    app_services = [s for s in services
                    if not s.startswith("grpc.reflection.")
                    and s != "grpc.health.v1.Health"]

    methods, schemas = [], {}
    for svc in app_services:
        text = describe(args, svc)
        found = parse_methods(svc, text)
        if not found:
            print("warn: no rpc lines parsed for %s" % svc, file=sys.stderr)
        methods.extend(found)

    if not args.no_messages:
        for mt in sorted({m["input_type"] for m in methods}):
            text = describe(args, mt)
            if text:
                schemas[mt] = parse_fields(text)

    inventory = {
        "target": args.target,
        "transport": ("plaintext" if args.plaintext
                      else "tls-insecure" if args.insecure else "tls"),
        "reflection": reflection,
        "services": services,
        "methods": methods,
        "message_schemas": schemas,
    }

    units = []
    for i, m in enumerate(methods, 1):
        fields = schemas.get(m["input_type"], [])
        targets = [cap(args.target), cap(m["full"]), cap(m["input_type"])]
        targets += [cap("field:%s %s" % (f["type"], f["name"])) for f in fields]
        units.append({
            "id": "grpc-%03d" % i,
            "title": "grpc-method-authz",
            "targets": targets,
            "hints": hints_for(m, fields),
        })

    atomic_write(prefix + "-inventory.json", inventory)
    atomic_write(prefix + "-units.json", units)
    print("services=%d methods=%d reflection=%s"
          % (len(app_services), len(methods), reflection))


if __name__ == "__main__":
    main()
