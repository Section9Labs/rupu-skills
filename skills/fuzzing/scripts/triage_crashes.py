#!/usr/bin/env python3
"""triage_crashes.py - replay, classify, and deduplicate fuzzer crashes.

Scans an AFL++ / honggfuzz / libFuzzer output directory for crash files,
replays each one under the target binary (ASan build recommended), parses
the ASan / stderr output to classify the bug (bug class, faulting function,
top frames), deduplicates by top-frame signature, prints a table, and emits
a rupu work-units JSON array (one unit per unique crash signature).

Usage:
  python3 scripts/triage_crashes.py --crash-dir out \
      --target './target_asan @@' [--stdin] [--timeout 10] \
      [--units units.json] [--max-per-sig 3]

Target command: a shell-style string; '@@' is replaced with the crash file
path. With --stdin (or when '@@' is absent) the crash bytes are piped to
stdin instead. If the target is missing or not runnable, the script still
inventories crash files and emits work units with bug_class "unknown".

Standard library only. Signed: vulture (peach-cape).
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

# ---------------------------------------------------------------- discovery

AFL_CRASH_RE = re.compile(r"^id[:_]")
HF_CRASH_RE = re.compile(r"\.fuzz$|^SIG[A-Z]+\.")
LF_CRASH_RE = re.compile(r"^(crash|oom|timeout|leak)-[0-9a-f]+$")


def find_crashes(root):
    """Yield crash file paths from AFL++, honggfuzz, libFuzzer layouts."""
    crashes = []
    if os.path.isfile(root):
        return [root]
    for dirpath, _dirnames, filenames in os.walk(root):
        in_afl_crashdir = os.path.basename(dirpath) in ("crashes", "hangs")
        for fn in sorted(filenames):
            if fn == "README.txt":
                continue
            path = os.path.join(dirpath, fn)
            if in_afl_crashdir and AFL_CRASH_RE.match(fn):
                crashes.append(path)
            elif HF_CRASH_RE.search(fn):
                crashes.append(path)
            elif LF_CRASH_RE.match(fn):
                crashes.append(path)
    return crashes


# ----------------------------------------------------------------- replay

def replay(target_argv, crash_path, use_stdin, timeout, env):
    """Run the target on one crash file; return (returncode, stderr_text)."""
    if use_stdin:
        argv = target_argv
    else:
        argv = [a.replace("@@", crash_path) for a in target_argv]
    try:
        with open(crash_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return None, "cannot read crash file: %s" % e
    try:
        proc = subprocess.run(
            argv,
            input=data if use_stdin else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except FileNotFoundError:
        return None, "target not found"
    except OSError as e:
        return None, "exec failed: %s" % e


# ----------------------------------------------------------------- parsing

ASAN_ERR_RE = re.compile(
    r"ERROR: (?:Address|Memory|Leak|Undefined|Thread)?Sanitizer:?\s*"
    r"([A-Za-z0-9_-]+(?:-[A-Za-z0-9_-]+)*)"
)
UBSAN_RE = re.compile(r"runtime error: ([^\n]+)")
FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")
NOISE_FRAMES = (
    "__asan", "__ubsan", "__msan", "__lsan", "__sanitizer", "__interceptor",
    "asan_", "interceptor_", "__libc_start", "_start", "fuzzer::",
    "LLVMFuzzerTestOneInput_wrapper",
)

SIGNALS = {
    4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV",
}


def clean_frames(text, limit=8):
    frames = []
    for m in FRAME_RE.finditer(text):
        fn = m.group(1)
        if any(fn.startswith(n) or n in fn for n in NOISE_FRAMES):
            continue
        frames.append(fn)
        if len(frames) >= limit:
            break
    return frames


def classify(returncode, stderr):
    """Return (bug_class, frames). bug_class is an ASan-style keyword."""
    bug = None
    m = ASAN_ERR_RE.search(stderr or "")
    if m:
        bug = m.group(1)
        if bug == "SEGV":
            bug = "segv"
    elif UBSAN_RE.search(stderr or ""):
        bug = "ubsan-" + UBSAN_RE.search(stderr).group(1).split()[0]
    elif "stack smashing detected" in (stderr or ""):
        bug = "stack-buffer-overflow"
    elif "double free or corruption" in (stderr or ""):
        bug = "double-free"
    elif "free(): invalid" in (stderr or "") or "malloc(): " in (stderr or ""):
        bug = "heap-corruption"
    elif isinstance(returncode, int) and returncode < 0:
        bug = SIGNALS.get(-returncode, "signal-%d" % -returncode).lower()
    elif returncode == "timeout":
        bug = "timeout"
    frames = clean_frames(stderr or "")
    return bug or "unknown", frames


def slugify(s, maxlen=60):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:maxlen].strip("-") or "crash"


HINT_MAP = {
    "heap-buffer-overflow": "heap-exploitation",
    "heap-use-after-free": "heap-exploitation",
    "double-free": "heap-exploitation",
    "heap-corruption": "heap-exploitation",
    "stack-buffer-overflow": "rop-chains",
    "stack-use-after-return": "rop-chains",
}


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--crash-dir", required=True,
                    help="fuzzer output dir (AFL++ -o dir, honggfuzz crashdir, "
                         "libFuzzer artifact dir) or a single crash file")
    ap.add_argument("--target", default=None,
                    help="replay command, e.g. './target_asan @@' (shell-split; "
                         "@@ -> crash path). Omit to inventory only.")
    ap.add_argument("--stdin", action="store_true",
                    help="feed crash bytes on stdin instead of @@")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--units", default="units.json",
                    help="output work-units JSON array (default units.json)")
    ap.add_argument("--max-per-sig", type=int, default=3,
                    help="crash inputs kept per unique signature")
    ap.add_argument("--save-reports", action="store_true",
                    help="write <crash>.asan.txt next to each replayed input")
    args = ap.parse_args()

    crashes = find_crashes(args.crash_dir)
    if not crashes:
        print("[!] no crash files found under %s" % args.crash_dir)
        print("    expected: out/*/crashes/id:*  |  *.fuzz  |  crash-<sha1>")
        with open(args.units, "w") as f:
            f.write("[]\n")
        return 0
    print("[*] %d crash file(s) found" % len(crashes))

    target_argv, can_replay = None, False
    if args.target:
        target_argv = shlex.split(args.target)
        exe = target_argv[0]
        if shutil.which(exe) or (os.path.isfile(exe) and os.access(exe, os.X_OK)):
            can_replay = True
            if "@@" not in args.target:
                args.stdin = True
        else:
            print("[!] target %r not found/executable - inventory-only mode" % exe)
    else:
        print("[!] no --target given - inventory-only mode (bug_class=unknown)")

    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS",
                   "abort_on_error=1:symbolize=1:detect_leaks=0:"
                   "allocator_may_return_null=1")
    env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")

    groups = {}  # sig -> {bug_class, frames, inputs: []}
    for path in crashes:
        if can_replay:
            rc, stderr = replay(target_argv, path, args.stdin, args.timeout, env)
            bug, frames = classify(rc, stderr)
            if args.save_reports and stderr:
                try:
                    with open(path + ".asan.txt", "w") as f:
                        f.write(stderr)
                except OSError:
                    pass
        else:
            bug, frames, stderr = "unknown", [], ""
            # honggfuzz encodes the signal in the filename; salvage it
            m = re.match(r"(SIG[A-Z]+)", os.path.basename(path))
            if m:
                bug = m.group(1).lower()
        top = frames[0] if frames else "?"
        sig_src = bug + "|" + "|".join(frames[:3])
        sig = hashlib.sha1(sig_src.encode()).hexdigest()[:8]
        g = groups.setdefault(sig, {"bug_class": bug, "frames": frames,
                                    "faulting_function": top, "inputs": []})
        g["inputs"].append(path)

    # ---- table
    print()
    print("%-10s %-28s %-24s %s" % ("SIG", "BUG CLASS", "FAULTING FN", "COUNT"))
    print("-" * 76)
    for sig, g in sorted(groups.items(), key=lambda kv: -len(kv[1]["inputs"])):
        print("%-10s %-28s %-24s %d" % (sig, g["bug_class"][:28],
                                        g["faulting_function"][:24],
                                        len(g["inputs"])))
    print("-" * 76)
    print("[*] %d unique signature(s) from %d crash(es)"
          % (len(groups), len(crashes)))

    # ---- work units
    units = []
    for sig, g in sorted(groups.items()):
        hints = {"gdb-debugging", "pwntools", "vuln-classes"}
        extra = HINT_MAP.get(g["bug_class"])
        if extra:
            hints.add(extra)
        uid = slugify("%s-%s-%s" % (g["bug_class"], g["faulting_function"], sig))
        targets = []
        for inp in sorted(g["inputs"], key=lambda p: os.path.getsize(p)
                          if os.path.exists(p) else 0)[: args.max_per_sig]:
            targets.append({
                "file": os.path.abspath(target_argv[0]) if target_argv
                        else args.crash_dir,
                "crash_input_path": os.path.abspath(inp),
                "bug_class": g["bug_class"],
                "faulting_function": g["faulting_function"],
                "frames": g["frames"],
            })
        units.append({
            "id": uid,
            "title": "%s in %s (%d crashing input%s)"
                     % (g["bug_class"], g["faulting_function"],
                        len(g["inputs"]), "s" if len(g["inputs"]) != 1 else ""),
            "targets": targets,
            "hints": sorted(hints),
        })

    with open(args.units, "w") as f:
        json.dump(units, f, indent=2)
        f.write("\n")
    print("[*] wrote %d work unit(s) -> %s" % (len(units), args.units))
    print("[*] next: load the vuln-classes skill on each unit; "
          "assets.mark the binary (triaged) and faulting symbols")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
