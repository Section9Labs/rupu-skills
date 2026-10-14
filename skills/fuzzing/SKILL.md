---
name: fuzzing
description: Coverage-guided fuzzing with AFL++, honggfuzz, and libFuzzer to discover crashing inputs in native code — write one harness that drives all three engines, instrument with sanitizers and CmpLog, seed and minimize a corpus, run multi-core campaigns, then triage, minimize, and deduplicate crashes into work units for vuln-classes and the exploitation skills. Use whenever you have a binary or library (with or without source) and need memory-safety bugs.
metadata:
  author: Section9Labs
---

# Fuzzing

Coverage-guided fuzzing finds crashing inputs by mutating a corpus and keeping
mutants that reach new code. The pipeline is always the same:

1. **Pick a harness point** — a function that consumes untrusted bytes
   (parser, decoder, protocol handler) or the whole program via argv/stdin/file.
2. **Instrument** — compile with the fuzzer's compiler wrapper, plus ASan/UBSan
   so silent corruption becomes a crash.
3. **Seed a corpus** — small, valid, diverse inputs; add a dictionary of
   magic values/keywords.
4. **Run** — multi-core, with CmpLog/laf-intel to defeat magic-byte comparisons.
5. **Triage** — reproduce, read the ASan report, minimize (`afl-tmin`,
   `-minimize_crash=1`), dedupe by stack signature.
6. **Confirm & hand off** — classify with the `vuln-classes` skill, develop
   the primitive with `gdb-debugging` / `heap-exploitation` / `rop-chains` /
   `pwntools`.

Details per engine: `references/aflplusplus.md`, `references/honggfuzz.md`,
`references/libfuzzer.md`. Harness craft: `references/harnessing.md`.
Output wiring: `references/rupu.md`.

## 1. The harness — one contract, three engines

The libFuzzer entrypoint is the shared contract. Write it once; it drives
libFuzzer natively, AFL++ via `afl-clang-fast`'s libFuzzer shim
(`afl-clang-fast -fsanitize=fuzzer`), and honggfuzz via `hfuzz-cc`'s shim:

```c
// harness.c — fuzz a parsing function
#include <stdint.h>
#include <stddef.h>
#include "mylib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;              // reject trivially-short inputs
    mylib_ctx_t *ctx = mylib_new();
    mylib_parse(ctx, data, size);        // the target
    mylib_free(ctx);                     // free everything: leaks poison ASan
    return 0;                            // always 0; crash = bug
}
```

Rules: deterministic (no rand/time/globals carried across calls), no
`exit()`, free all allocations, no writes to `data`. One-time setup goes in
`LLVMFuzzerInitialize(int *argc, char ***argv)` or a static-init guard.

**AFL++ persistent mode** (source form, ~10–20x faster than fork-per-input):

```c
#include "mylib.h"
__AFL_FUZZ_INIT();

int main(void) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();                        // defer forkserver past setup
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;   // after __AFL_INIT
    while (__AFL_LOOP(10000)) {          // 10000 iters per fork
        int len = __AFL_FUZZ_TESTCASE_LEN;
        mylib_parse_once(buf, len);
    }
    return 0;
}
```

**honggfuzz persistent mode**: same idea with `HF_ITER`:

```c
int main(void) {
    const uint8_t *buf; size_t len;
    for (;;) {
        HF_ITER(&buf, &len);             // blocks for next testcase
        mylib_parse_once(buf, len);
    }
}
```

See `references/harnessing.md` for stateful targets, splitting input bytes
into multiple parameters, and resetting global state.

## 2. AFL++

Build (pick the best instrumentation available):

```sh
# preferred: LTO (collision-free edges), else afl-clang-fast; afl-gcc-fast for gcc-only code
CC=afl-clang-lto CXX=afl-clang-lto++ ./configure --disable-shared && make
# sanitizers — build a *separate* ASan binary (keep one plain for speed):
AFL_USE_ASAN=1 CC=afl-clang-fast make        # or AFL_USE_UBSAN=1, AFL_USE_MSAN=1
# CmpLog (input-to-state, redqueen): second binary built with:
AFL_LLVM_CMPLOG=1 CC=afl-clang-fast make && cp ./target ./target.cmplog
# comparison splitting (alternative/complement to CmpLog):
AFL_LLVM_LAF_ALL=1 CC=afl-clang-fast make
```

Run:

```sh
afl-fuzz -i corpus -o out -x dict.txt -c ./target.cmplog -- ./target @@
```

- `@@` is replaced by the testcase file path; omit it and AFL++ feeds stdin.
- `-t 1000` timeout in ms (`-t 1000+` to skip, not abort, on timeout);
  `-m none` for ASan builds (ASan maps TBs of shadow).
- Multi-core: one master `-M main` (does deterministic steps) plus
  secondaries `-S s01 ... -S sNN`, all with the same `-o out`; vary one
  secondary per feature: one ASan build, one CmpLog `-c`, one laf build,
  different power schedules `-p fast|explore|exploit|coe|rare`, one `-D`
  (deterministic) node.
- Black-box binaries (no source): QEMU mode `-Q`; FRIDA mode `-O`
  (needs `afl-fuzz -Q/-O` plus the plain binary). CORESIGHT/Nyx exist for
  special cases.

Status screen: watch **corpus count / pending favs** (still finding paths?),
**exec speed** (<500/s per core = fix the harness or use persistent mode),
**saved crashes / hangs**, **stability** (<90% = nondeterminism in target),
and `cycles done` turning green (coverage plateau — rotate seeds/dictionary).
`afl-whatsup out/` summarizes a multi-node campaign. Full flag reference and
campaign patterns: `references/aflplusplus.md`.

## 3. honggfuzz

```sh
CC=hfuzz-cc CXX=hfuzz-cc++ make          # or hfuzz-clang / hfuzz-clang++
hfuzz-cc -fsanitize=address harness_hf.c mylib.a -o target_hf
```

Run:

```sh
honggfuzz -i corpus -o corpus_out -n 8 -- ./target_hf ___FILE___   # file input
honggfuzz -i corpus -P -- ./target_persist                          # persistent (HF_ITER / LLVMFuzzerTestOneInput)
honggfuzz -i corpus --linux_perf_bts_edge -- ./target ___FILE___    # HW branch feedback (works on uninstrumented bins)
honggfuzz -i corpus -M -- ./target ___FILE___                       # corpus minimization mode
```

`-n N` threads share one corpus automatically; crashes land in the CWD (or
`--crashdir`) as `SIGSEGV.PC.*.fuzz` files plus a `HONGGFUZZ.REPORT.TXT`.
Hardware feedback: `--linux_perf_instr`, `--linux_perf_branch`,
`--linux_perf_bts_edge`, `--linux_perf_ipt_block` — the way to get
coverage on black-box binaries with perf access. Details:
`references/honggfuzz.md`.

## 4. libFuzzer

```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c mylib.a -o fuzz
./fuzz corpus/ -max_len=4096 -jobs=8 -workers=8 -dict=dict.txt
```

- First positional dir = output corpus; extra dirs are read-only seeds.
- Crash is written to CWD as `crash-<sha1>` (also `leak-*`, `timeout-*`,
  `oom-*`); replay with `./fuzz crash-...`.
- `-merge=1 minimized/ corpus/` → coverage-minimized corpus into `minimized/`.
- `-minimize_crash=1 -runs=100000 crash-file` → minimal reproducer.
- libFuzzer is in LLVM maintenance mode but remains the standard in-process
  engine and the harness ABI everything else consumes. Flags and output
  reading: `references/libfuzzer.md`.

## 5. Corpus and dictionary

- Seeds: real-world samples of the format, each < a few KB, deduped by
  coverage: `afl-cmin -i seeds -o corpus -- ./target @@`, then per-file
  `afl-tmin`. libFuzzer `-merge=1` and honggfuzz `-M` do the same job.
- Dictionary: AFL++ ships format dicts in `dictionaries/`; auto-generate at
  LTO build time with `AFL_LLVM_DICT2FILE=/path/dict.txt`; libFuzzer/AFL++
  share the format (`kw="PNG\x89"`). CmpLog usually beats dictionaries for
  magic values — run both.

## 6. Triage

For every crash:

1. **Reproduce**: `./target < crash` or `./target crash` (match the harness
   I/O), ASan build, `ASAN_OPTIONS=abort_on_error=1:symbolize=1`. libFuzzer:
   `./fuzz crash-<sha1>`.
2. **Read the ASan report**: first line gives the bug class
   (`heap-buffer-overflow`, `heap-use-after-free`, `stack-buffer-overflow`,
   `double-free`, `SEGV on unknown address`, ...), READ/WRITE + size, and the
   stack. The top non-interceptor frame is the faulting function.
3. **Minimize**: `afl-tmin -i crash -o crash.min -- ./target @@`;
   libFuzzer `./fuzz -minimize_crash=1 -runs=100000 crash-file`.
4. **Dedupe**: corpus-level `afl-cmin`; crash-level by (bug class, top ~3
   non-sanitizer frames) — that is exactly what the script does.
5. **Classify & hand off**: feed the report to the `vuln-classes` skill to
   name the class and the primitive; then `gdb-debugging` to inspect the
   crash state, and `rop-chains`/`heap-exploitation`/`format-string-exploitation`/
   `pwntools` to build the exploit.

### scripts/triage_crashes.py

Scans an AFL++ (`out/*/crashes/id:*`), honggfuzz (`*.fuzz`), or libFuzzer
(`crash-*`) output directory, replays each crash under the target, parses
ASan/stderr, classifies and dedupes by top-frame signature, prints a table,
and writes a rupu work-units JSON array (one unit per unique crash):

```sh
python3 scripts/triage_crashes.py --crash-dir out \
    --target './target_asan @@' --timeout 10 --units units.json
# stdin targets: --target './target_asan' --stdin
# no replay possible (target absent): script still inventories and emits units
```

Each unit: `{id, title, targets:[{file, crash_input_path, bug_class,
faulting_function, frames:[...]}], hints:["gdb-debugging","pwntools","vuln-classes"]}`.

## 7. Record results (rupu)

After triage (see `references/rupu.md` and the shared `work-units` and
`finding-report` skills):

- `units.json` is the fan-out input for `for_each:` — one unit per unique
  crash signature.
- `assets.mark` the fuzzed binary as `binary:file` at depth `triaged`
  (crashes found) or `analyzed` (crashes classified); mark each faulting
  function as `binary:symbol`, depth `vuln-identified` once `vuln-classes`
  confirms the class.
- A confirmed exploitable crash (controlled PC, controlled write, ASan class
  with a known primitive) → `findings.report` per the `finding-report` skill,
  with the minimized input and ASan report as evidence.
- Keep raw fuzzer output dirs (`out/`, crash files, `fuzzer_stats`,
  `plot_data`, `HONGGFUZZ.REPORT.TXT`) in the run workspace as evidence.
