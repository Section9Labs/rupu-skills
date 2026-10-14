# honggfuzz reference

honggfuzz (https://github.com/google/honggfuzz) is a multi-threaded,
feedback-driven fuzzer notable for Linux hardware-assisted coverage
(perf BTS/Intel PT) — it can get edge coverage on **uninstrumented**
binaries — and a very low-friction multi-threaded corpus-sharing model.

## Building targets

Compiler wrappers inject SanitizerCoverage-based instrumentation and link
`libhfuzz` (persistent-mode runtime + libFuzzer shim):

```sh
hfuzz-cc harness.c mylib.a -o target          # auto-detects clang/gcc
hfuzz-clang / hfuzz-clang++ / hfuzz-gcc / hfuzz-g++   # explicit variants
hfuzz-cc -fsanitize=address,undefined ...     # sanitizers: plain clang flags
CC=hfuzz-cc CXX=hfuzz-cc++ ./configure && make
```

A file containing `LLVMFuzzerTestOneInput` compiled with `hfuzz-cc` becomes a
persistent-mode binary automatically (libhfuzz supplies `main`). The raw
persistent API is:

```c
#include <libhfuzz/libhfuzz.h>   // or just declare: void HF_ITER(const uint8_t**, size_t*);
int main(void) {
    const uint8_t *buf; size_t len;
    for (;;) {
        HF_ITER(&buf, &len);
        parse(buf, len);
    }
}
```

## Running

```sh
honggfuzz -i corpus -- ./target ___FILE___        # file-input target
honggfuzz -i corpus -s -- ./target                # feed via stdin (-s)
honggfuzz -i corpus -P -- ./target_persist        # persistent mode (-P; auto-detected for libhfuzz bins)
```

Key flags:

- `-i dir` input corpus dir — honggfuzz **writes new coverage inputs back
  into it** (it is in/out); `-o dir` / `--output` for a separate output
  corpus on newer versions.
- `-n N` number of fuzzing threads (default = cores/2). All threads share
  the corpus and coverage state in-process — no sync setup needed.
- `-t sec` per-run timeout; `-F bytes` max input size.
- `-w dict.txt` dictionary (AFL format); `-E KEY=VAL` env for the target.
- `--crashdir dir` where crash inputs go (default CWD); crash files are
  named like `SIGSEGV.PC.7f...ADDR...fuzz` plus `HONGGFUZZ.REPORT.TXT`
  (append-only text report: signal, PC, fault address, stack).
- `-M` **minimize**: rewrites the corpus in `-i` to a coverage-minimal set,
  then exits. Run periodically on long campaigns.
- `--exit_upon_crash` stop at first crash; `-v` no TUI (log lines);
  `-V` verifier: re-runs crashes to confirm reproducibility before saving.
- `--only_printable`, `--mutations_per_run`, `--ext` (output extension) for
  format-constrained targets.

## Hardware feedback (uninstrumented binaries)

Requires perf access (`kernel.perf_event_paranoid` ≤ 1, run as root
otherwise):

- `--linux_perf_instr` — instruction-count feedback (coarse).
- `--linux_perf_branch` — branch-count feedback (coarse).
- `--linux_perf_bts_edge` — Intel BTS edge coverage (real edges, pre-Skylake
  or wherever BTS exists; slow but precise).
- `--linux_perf_ipt_block` — Intel PT block coverage (fast, modern CPUs;
  needs libipt).

Combine with `-s`/`___FILE___` to fuzz closed-source parsers:

```sh
honggfuzz -i corpus --linux_perf_bts_edge -n 4 -- ./blackbox_parser ___FILE___
```

Software NetBSD/POSIX fallbacks and sanitizer-coverage (`--sancov`) also
exist; with instrumented builds no flag is needed (default sancov feedback).

## Reading output

TUI shows: `Iterations`, `Speed` (execs/s global and per-thread), `Crashes`
(unique vs total), `Timeouts`, `Coverage` (edge/pc counts). The log form
(`-v`) prints `Size:... (i,b,hw,ed,ip,cmp): ...` deltas when a new input is
saved — `ed` is edges. `HONGGFUZZ.REPORT.TXT` entries look like:

```
ORIG_FNAME: ...
FUZZ_FNAME: SIGSEGV.PC.0x4011d2.STACK.1a2b3c.CODE.1.ADDR.0x41414141.INSTR.mov.fuzz
SIGNAL: SIGSEGV, PC: 0x4011d2, FAULT ADDRESS: 0x41414141
STACK: #0 0x4011d2 parse_header ...
```

Dedup is built in (by stack hash in the filename `STACK.<hash>`), but re-run
`scripts/triage_crashes.py` for cross-engine dedupe and work-unit emission.

## Interop

- honggfuzz accepts/produces plain files — point AFL++ at its corpus with
  `afl-fuzz -F /path/honggfuzz_corpus` and vice versa (copy AFL++ `queue/`
  files into the honggfuzz `-i` dir; it picks them up live).
- The same `LLVMFuzzerTestOneInput` harness object links against libFuzzer,
  AFL++'s shim, and libhfuzz — build all three from one source.
