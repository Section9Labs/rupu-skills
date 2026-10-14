#!/usr/bin/env python3
"""angr_solve.py — symbolic-execution solve template.

Sets up symbolic stdin for a binary, explores to a find address (or until a success
string appears on stdout) while avoiding failure addresses/strings, and prints the
input bytes that reach the target. Can also hunt unconstrained (hijackable) states.

Usage:
  python3 scripts/angr_solve.py <binary> [options]

Examples:
  python3 scripts/angr_solve.py ./crackme --find 0x401a2c --avoid 0x401b00,0x401b40
  python3 scripts/angr_solve.py ./crackme --find-str "Correct" --avoid-str "Wrong" \
      --stdin-len 40 --printable --out solve.json --work-units units.json
  python3 scripts/angr_solve.py ./server --hunt-unconstrained --stdin-len 400

Only the Python 3 standard library is required to *start* this script; solving needs
`pip install angr` (use a venv; angr pins claripy/cle/pyvex versions).

TROUBLESHOOTING generated angr scripts (the usual breakages):
  * Hangs before main or inside __libc_start_main
      -> use entry_state (this script's default), NOT full_init_state; or start at
         main with a blank_state and place stdin/args yourself.
  * "unsupported SimProcedure" / unresolved-call warnings
      -> harmless stubs from auto_load_libs=False; hook the symbol with a real
         angr.SIM_PROCEDURES model only if its behavior matters.
  * simgr.found stays empty
      -> PIE: angr rebases to 0x400000; your disassembler's addresses may differ.
         Pass --base to pin, or recompute find = 0x400000 + file_offset.
      -> an un-avoided exit()/error basin consumed all paths: add more --avoid.
      -> stdin too short to satisfy a length check: raise --stdin-len.
  * Memory climbs forever
      -> --dfs, --veritesting, --lazy here; or hook the hot (hash/strlen) function
         with a SimProcedure (see references/simprocedures.md).
  * Solution bytes are unprintable garbage
      -> rerun with --printable.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

INSTALL_HELP = """\
[!] angr is not installed (import failed: {err})

    Install into a virtualenv (recommended -- angr pins many dependencies):
        python3 -m venv venv && . venv/bin/activate
        python3 -m pip install angr
"""


def parse_int(s):
    return int(s, 0)


def parse_addr_list(s):
    return [int(x, 0) for x in s.split(",") if x.strip()]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_argparser():
    ap = argparse.ArgumentParser(
        description="Solve for stdin that reaches a target state with angr.",
        epilog="See the module docstring for a troubleshooting guide.")
    ap.add_argument("binary", help="target binary")
    ap.add_argument("--find", type=parse_addr_list, default=None,
                    help="find address(es), comma-separated, 0x-hex ok")
    ap.add_argument("--find-str", default=None,
                    help="success string that must appear on stdout")
    ap.add_argument("--avoid", type=parse_addr_list, default=[],
                    help="avoid address(es), comma-separated")
    ap.add_argument("--avoid-str", default=None,
                    help="failure string on stdout that marks a dead path")
    ap.add_argument("--stdin-len", type=int, default=64,
                    help="symbolic stdin size in bytes (default 64)")
    ap.add_argument("--printable", action="store_true",
                    help="constrain stdin bytes to printable ASCII 0x20..0x7e")
    ap.add_argument("--base", type=parse_int, default=None,
                    help="force load base (match your disassembler for PIE)")
    ap.add_argument("--full-init", action="store_true",
                    help="use full_init_state instead of entry_state")
    ap.add_argument("--veritesting", action="store_true")
    ap.add_argument("--lazy", action="store_true", help="add LAZY_SOLVES")
    ap.add_argument("--dfs", action="store_true", help="depth-first exploration")
    ap.add_argument("--hunt-unconstrained", action="store_true",
                    help="run until an unconstrained (symbolic PC) state appears")
    ap.add_argument("--max-steps", type=int, default=0,
                    help="cap exploration steps (0 = unlimited)")
    ap.add_argument("--out", default="solve.json", help="JSON result path")
    ap.add_argument("--work-units", default=None,
                    help="also emit a rupu work-units JSON array here")
    return ap


def main():
    args = build_argparser().parse_args()

    if not (args.find or args.find_str or args.hunt_unconstrained):
        sys.stderr.write("[!] need --find, --find-str, or --hunt-unconstrained\n")
        return 1
    if not os.path.isfile(args.binary):
        sys.stderr.write(f"[!] binary not found: {args.binary}\n")
        return 1

    try:
        import angr
        import claripy
    except ImportError as e:
        sys.stderr.write(INSTALL_HELP.format(err=e))
        return 1

    import logging
    logging.getLogger("angr").setLevel(logging.ERROR)  # silence stub-warning spam

    main_opts = {"base_addr": args.base} if args.base is not None else {}
    proj = angr.Project(args.binary, auto_load_libs=False, main_opts=main_opts)
    print(f"[*] loaded {args.binary}: arch={proj.arch.name} entry={hex(proj.entry)} "
          f"base={hex(proj.loader.main_object.min_addr)} "
          f"pie={proj.loader.main_object.pic}")

    flag = claripy.BVS("stdin_flag", 8 * args.stdin_len)
    stdin = angr.SimFileStream(name="stdin", content=flag, has_end=True)

    opts = set()
    if args.lazy:
        opts.add(angr.options.LAZY_SOLVES)

    factory = (proj.factory.full_init_state if args.full_init
               else proj.factory.entry_state)
    state = factory(stdin=stdin, add_options=opts)

    if args.printable:
        for i in range(args.stdin_len):
            b = flag.get_byte(i)
            state.solver.add(b >= 0x20, b <= 0x7e)

    simgr = proj.factory.simgr(state,
                               veritesting=args.veritesting,
                               save_unconstrained=True)
    if args.dfs:
        simgr.use_technique(angr.exploration_techniques.DFS())

    find_addrs = set(args.find or [])
    find_bytes = args.find_str.encode() if args.find_str else None
    avoid_addrs = set(args.avoid)
    avoid_bytes = args.avoid_str.encode() if args.avoid_str else None

    def is_find(s):
        if s.addr in find_addrs:
            return True
        if find_bytes and find_bytes in s.posix.dumps(1):
            return True
        return False

    def is_avoid(s):
        if s.addr in avoid_addrs:
            return True
        if avoid_bytes and avoid_bytes in s.posix.dumps(1):
            return True
        return False

    steps = [0]

    def step_func(sm):
        sm.drop(stash="avoid")                 # keep memory flat
        steps[0] += 1
        if steps[0] % 100 == 0:
            print(f"    step {steps[0]}: active={len(sm.active)} "
                  f"found={len(sm.found)} unconstrained={len(sm.unconstrained)}")
        return sm

    result = {
        "binary": os.path.abspath(args.binary),
        "sha256": sha256_file(args.binary),
        "arch": proj.arch.name,
        "stdin_len": args.stdin_len,
        "mode": "unconstrained-hunt" if args.hunt_unconstrained else "find",
        "find": [hex(a) for a in find_addrs] + ([args.find_str] if args.find_str else []),
        "avoid": [hex(a) for a in avoid_addrs] + ([args.avoid_str] if args.avoid_str else []),
        "solution": None,
        "unconstrained": None,
    }

    print("[*] exploring...")
    try:
        if args.hunt_unconstrained:
            while simgr.active and not simgr.unconstrained:
                simgr.step()
                step_func(simgr)
                if args.max_steps and steps[0] >= args.max_steps:
                    print("[!] step cap reached"); break
        else:
            kw = dict(find=is_find, avoid=is_avoid, step_func=step_func)
            if args.max_steps:
                kw["n"] = args.max_steps
            simgr.explore(**kw)
    except KeyboardInterrupt:
        print("[!] interrupted — reporting whatever was found so far")

    rc = 1

    if simgr.unconstrained:
        s = simgr.unconstrained[0]
        print(f"[+] UNCONSTRAINED state: pc is symbolic ({s.regs.pc})")
        marker = 0x41414141 if proj.arch.bits == 32 else 0x4141414141414141
        s.add_constraints(s.regs.pc == marker)
        if s.satisfiable():
            crash = s.posix.dumps(0)
            off = crash.find(b"A" * (proj.arch.bits // 8))
            print(f"[+] stdin that sets PC = {hex(marker)} "
                  f"({len(crash)} bytes, marker offset {off}):")
            print(f"    hex: {crash.hex()}")
            result["unconstrained"] = {
                "pc_expr": str(s.regs.pc),
                "crash_stdin_hex": crash.hex(),
                "crash_stdin_b64": base64.b64encode(crash).decode(),
                "marker": hex(marker),
                "marker_offset": off,
            }
            print("[*] next: hand offset + input to the pwntools / rop-chains skills")
            rc = 0
        else:
            print("[!] pc symbolic but not fully controllable with this input length")

    if simgr.found:
        s = simgr.found[0]
        sol_sym = s.solver.eval(flag, cast_to=bytes)
        sol_stdin = s.posix.dumps(0)
        print(f"[+] FOUND state at {hex(s.addr)}")
        print(f"    symbolic var solution : {sol_sym!r}")
        print(f"    stdin to reach target : {sol_stdin!r}")
        print(f"    stdin hex             : {sol_stdin.hex()}")
        print(f"    stdout on this path   : {s.posix.dumps(1)!r}")
        print(f"[*] verify natively:  ./target < solution.bin  "
              f"(bytes also in {args.out})")
        result["solution"] = {
            "found_addr": hex(s.addr),
            "flag_bytes_hex": sol_sym.hex(),
            "stdin_hex": sol_stdin.hex(),
            "stdin_b64": base64.b64encode(sol_stdin).decode(),
            "stdout": s.posix.dumps(1).decode("latin-1"),
        }
        rc = 0

    if rc != 0 and not simgr.found and not simgr.unconstrained:
        print(f"[!] nothing found. deadended={len(simgr.deadended)} "
              f"active={len(simgr.active)} errored={len(simgr.errored)}")
        print("    see the TROUBLESHOOTING section: python3 scripts/angr_solve.py -h")
        if simgr.errored:
            print(f"    first error: {simgr.errored[0]}")

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] result written: {args.out}")

    if args.work_units:
        write_work_units(args.work_units, result)
        print(f"[+] work units written: {args.work_units}")

    return rc


def slugify(s):
    out = "".join(c if (c.isalnum() and c.isascii()) else "-" for c in s.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-") or "unit"


def write_work_units(path, result):
    """rupu-ingestible JSON array; objects of exactly {id,title,targets,hints}."""
    name = os.path.basename(result["binary"])
    base_target = {"file": result["binary"], "sha256": result["sha256"],
                   "arch": result["arch"]}
    units = []
    if result.get("unconstrained"):
        u = result["unconstrained"]
        units.append({
            "id": slugify(f"angr-{name}-unconstrained-{result['sha256'][:12]}"),
            "title": f"{name}: unconstrained state — stdin controls PC "
                     f"(marker offset {u['marker_offset']})",
            "targets": [base_target],
            "hints": sorted(["pwntools", "rop-chains"]),
        })
    if result.get("solution"):
        sol = result["solution"]
        t = dict(base_target)
        t["vaddr"] = sol["found_addr"]
        units.append({
            "id": slugify(f"angr-{name}-solved-{sol['found_addr']}"),
            "title": f"{name}: input solved to reach {sol['found_addr']}",
            "targets": [t],
            "hints": sorted(["finding-report", "qiling-unicorn"]),
        })
    if not units:
        units.append({
            "id": slugify(f"angr-{name}-unsolved-{result['sha256'][:12]}"),
            "title": f"{name}: exploration inconclusive — needs hooks/avoids tuning",
            "targets": [base_target],
            "hints": sorted(["angr", "qiling-unicorn"]),
        })
    with open(path, "w") as f:
        json.dump(units, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
