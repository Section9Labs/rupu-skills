#!/usr/bin/env python3
"""qiling_run.py — generic Qiling emulation + instrumentation template.

Loads a target binary under a rootfs, installs:
  * a basic-block hook that logs every executed block address (image-relative too),
  * an optional hook at a user-given function address that dumps its arguments
    (ABI-aware) and dereferences pointer-looking args as strings,
then runs the target and writes a JSON trace, plus an optional rupu work-units file.

Usage:
  python3 scripts/qiling_run.py <target> <rootfs> [options]

Examples:
  python3 scripts/qiling_run.py squashfs-root/usr/sbin/httpd squashfs-root \
      --arg -p --arg 8080 --multithread --out trace.json
  python3 scripts/qiling_run.py squashfs-root/www/cgi-bin/login.cgi squashfs-root \
      --env REQUEST_METHOD=POST --env QUERY_STRING=user=admin \
      --func 0x40a310 --nargs 3 --work-units units.json

Only the Python 3 standard library is required to *start* this script; the actual
emulation needs `pip install qiling` (which installs unicorn/capstone).
"""

import argparse
import hashlib
import json
import os
import sys

INSTALL_HELP = """\
[!] Qiling / Unicorn is not installed (import failed: {err})

    Install with:
        python3 -m pip install qiling
    (this pulls in unicorn, capstone and keystone-engine)

    If you only need raw single-routine emulation, `pip install unicorn`
    is enough -- see references/unicorn.md in this skill.
"""

# Argument registers per Qiling arch name; x86 uses the stack (handled separately).
ABI_ARG_REGS = {
    "x8664": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "arm": ["r0", "r1", "r2", "r3"],
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "mips": ["a0", "a1", "a2", "a3"],
    "riscv": ["a0", "a1", "a2", "a3", "a4", "a5"],
    "riscv64": ["a0", "a1", "a2", "a3", "a4", "a5"],
}

MAX_BLOCK_LOG = 200_000  # hard cap so long-running daemons don't eat all RAM


def parse_int(s):
    return int(s, 0)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_argparser():
    ap = argparse.ArgumentParser(
        description="Run a binary under Qiling with block tracing and arg dumping.")
    ap.add_argument("target", help="path to the target binary (inside/under rootfs)")
    ap.add_argument("rootfs", help="rootfs directory (squashfs-root or qiling prebuilt)")
    ap.add_argument("--arg", action="append", default=[],
                    help="extra argv entry for the target (repeatable)")
    ap.add_argument("--env", action="append", default=[], metavar="KEY=VAL",
                    help="environment variable for the target (repeatable)")
    ap.add_argument("--func", type=parse_int, default=None,
                    help="address of a function to dump arguments at (0x..., "
                         "image-relative unless --absolute)")
    ap.add_argument("--absolute", action="store_true",
                    help="treat --func/--begin/--end as absolute (already rebased)")
    ap.add_argument("--nargs", type=int, default=4,
                    help="how many arguments to dump at --func (default 4)")
    ap.add_argument("--begin", type=parse_int, default=None, help="ql.run begin address")
    ap.add_argument("--end", type=parse_int, default=None, help="ql.run end address")
    ap.add_argument("--timeout", type=int, default=0,
                    help="emulation timeout in microseconds (0 = none)")
    ap.add_argument("--multithread", action="store_true",
                    help="enable thread emulation (pthread daemons)")
    ap.add_argument("--verbose", choices=["off", "default", "debug", "disasm"],
                    default="default")
    ap.add_argument("--out", default="trace.json", help="JSON trace output path")
    ap.add_argument("--work-units", default=None,
                    help="also emit a rupu work-units JSON array to this path")
    return ap


def main():
    args = build_argparser().parse_args()

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except ImportError as e:
        sys.stderr.write(INSTALL_HELP.format(err=e))
        return 1

    if not os.path.isfile(args.target):
        sys.stderr.write(f"[!] target not found: {args.target}\n")
        return 1
    if not os.path.isdir(args.rootfs):
        sys.stderr.write(f"[!] rootfs is not a directory: {args.rootfs}\n")
        return 1

    env = {}
    for kv in args.env:
        if "=" not in kv:
            sys.stderr.write(f"[!] bad --env (need KEY=VAL): {kv}\n")
            return 1
        k, v = kv.split("=", 1)
        env[k] = v

    verbose = {
        "off": QL_VERBOSE.OFF,
        "default": QL_VERBOSE.DEFAULT,
        "debug": QL_VERBOSE.DEBUG,
        "disasm": QL_VERBOSE.DISASM,
    }[args.verbose]

    ql = Qiling([args.target] + args.arg, args.rootfs,
                env=env, verbose=verbose, multithread=args.multithread)

    base = ql.loader.images[0].base if ql.loader.images else 0
    arch_name = ql.arch.type.name.lower()  # e.g. 'x8664', 'arm', 'mips'

    def rebase(addr):
        if addr is None:
            return None
        return addr if args.absolute else base + addr

    trace = {
        "target": os.path.abspath(args.target),
        "sha256": sha256_file(args.target),
        "rootfs": os.path.abspath(args.rootfs),
        "argv": [args.target] + args.arg,
        "env": env,
        "arch": arch_name,
        "image_base": hex(base),
        "images": [{"path": img.path, "base": hex(img.base), "end": hex(img.end)}
                   for img in ql.loader.images],
        "blocks": [],            # executed block addresses (absolute hex)
        "blocks_truncated": False,
        "func_hits": [],         # arg dumps at --func
        "exit_code": None,
        "error": None,
    }

    seen = set()

    def on_block(ql_, addr, size):
        if len(trace["blocks"]) >= MAX_BLOCK_LOG:
            trace["blocks_truncated"] = True
            return
        if addr not in seen:
            seen.add(addr)
            trace["blocks"].append(hex(addr))

    ql.hook_block(on_block)

    def read_args(ql_, n):
        """Return up to n integer args per the arch ABI."""
        regs = ABI_ARG_REGS.get(arch_name)
        vals = []
        if regs:
            for name in regs[:n]:
                try:
                    vals.append(ql_.arch.regs.read(name))
                except Exception:
                    break
        else:
            # x86 cdecl: [esp+4], [esp+8], ... (esp points at return address)
            for i in range(n):
                try:
                    vals.append(ql_.arch.stack_read(ql_.arch.pointersize * (i + 1)))
                except Exception:
                    break
        return vals

    def deref_maybe_string(ql_, val):
        """If val looks like a pointer into mapped memory, grab up to 64 bytes."""
        try:
            raw = bytes(ql_.mem.read(val, 64))
        except Exception:
            return None
        s = raw.split(b"\x00", 1)[0]
        if s and all(32 <= c < 127 for c in s):
            return s.decode("ascii", "replace")
        return raw[:16].hex()

    if args.func is not None:
        func_abs = rebase(args.func)

        def on_func(ql_):
            vals = read_args(ql_, args.nargs)
            hit = {
                "pc": hex(ql_.arch.regs.arch_pc),
                "args": [hex(v) for v in vals],
                "derefs": [deref_maybe_string(ql_, v) for v in vals],
            }
            trace["func_hits"].append(hit)
            ql_.log.info(f"[qiling_run] func hit {hit['pc']} args={hit['args']} "
                         f"derefs={hit['derefs']}")

        ql.hook_address(on_func, func_abs)
        print(f"[*] arg-dump hook installed at {hex(func_abs)} "
              f"(base {hex(base)} + {hex(args.func) if not args.absolute else 'abs'})")

    print(f"[*] running {args.target} under {args.rootfs} (arch={arch_name}, "
          f"base={hex(base)})")
    try:
        run_kwargs = {}
        if args.begin is not None:
            run_kwargs["begin"] = rebase(args.begin)
        if args.end is not None:
            run_kwargs["end"] = rebase(args.end)
        if args.timeout:
            run_kwargs["timeout"] = args.timeout
        ql.run(**run_kwargs)
    except KeyboardInterrupt:
        trace["error"] = "interrupted by operator"
    except Exception as e:  # crash in the emulated target is a *result*, not a failure
        trace["error"] = f"{type(e).__name__}: {e}"
        print(f"[!] emulation stopped: {trace['error']}")
        try:
            print(f"    pc={hex(ql.arch.regs.arch_pc)} sp={hex(ql.arch.regs.arch_sp)}")
            trace["crash"] = {"pc": hex(ql.arch.regs.arch_pc),
                              "sp": hex(ql.arch.regs.arch_sp)}
        except Exception:
            pass

    try:
        trace["exit_code"] = ql.os.exit_code
    except Exception:
        pass

    with open(args.out, "w") as f:
        json.dump(trace, f, indent=2)
    print(f"[+] trace written: {args.out} "
          f"({len(trace['blocks'])} unique blocks, {len(trace['func_hits'])} func hits)")

    if args.work_units:
        write_work_units(args, trace)
        print(f"[+] work units written: {args.work_units}")

    return 0


def slugify(s):
    out = []
    for c in s.lower():
        out.append(c if (c.isalnum() and c.isascii()) else "-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "unit"


def write_work_units(args, trace):
    """Emit a rupu-ingestible JSON array: objects of exactly {id,title,targets,hints}."""
    name = os.path.basename(trace["target"])
    file_target = {
        "file": trace["target"],
        "sha256": trace["sha256"],
        "arch": trace["arch"],
    }
    units = []

    # One unit for the binary overall: it emulates; deepen the analysis.
    units.append({
        "id": slugify(f"emu-{name}-{trace['sha256'][:12]}"),
        "title": f"{name}: runs under Qiling ({trace['arch']}), "
                 f"{len(trace['blocks'])} blocks traced"
                 + (" — crashed during run" if trace.get("error") else ""),
        "targets": [file_target],
        "hints": sorted(["angr", "qiling-unicorn"]),
    })

    # One unit per distinct hooked-function hit site with its observed arguments.
    seen_pcs = set()
    for hit in trace["func_hits"]:
        if hit["pc"] in seen_pcs:
            continue
        seen_pcs.add(hit["pc"])
        t = dict(file_target)
        t["vaddr"] = hit["pc"]
        units.append({
            "id": slugify(f"emu-{name}-func-{hit['pc']}"),
            "title": f"{name}: hooked function {hit['pc']} reached, "
                     f"args={hit['args']}",
            "targets": [t],
            "hints": sorted(["angr", "pwntools", "qiling-unicorn"]),
        })

    with open(args.work_units, "w") as f:
        json.dump(units, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
