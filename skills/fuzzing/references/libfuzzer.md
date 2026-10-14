# libFuzzer reference

libFuzzer is LLVM's in-process, coverage-guided fuzzer. It is in
**maintenance mode** upstream (new work goes to FuzzTest/centipede), but it
remains the standard harness ABI, the easiest engine to start with, and
what OSS-Fuzz-style harnesses target. Everything here is still current.

## Build

```sh
clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c mylib.a -o fuzz
```

- `-fsanitize=fuzzer` links the libFuzzer runtime and enables
  SanitizerCoverage; combine freely with `address`, `undefined`,
  `memory` (MSan: whole dep tree must be MSan-built), `leak`.
- `-fsanitize=fuzzer-no-link` instruments a library without linking the
  runtime (link the runtime only into the final fuzz binary).
- `-O1 -g` keeps stacks readable; `-fno-omit-frame-pointer` helps too.
- The harness exports `int LLVMFuzzerTestOneInput(const uint8_t*, size_t)`;
  optional `LLVMFuzzerInitialize(int*, char***)` runs once;
  optional `LLVMFuzzerCustomMutator` / `LLVMFuzzerCustomCrossOver` for
  structure-aware fuzzing.

## Run

```sh
mkdir -p corpus && cp seeds/* corpus/
./fuzz corpus/ seeds2/ -max_len=4096 -dict=dict.txt -jobs=8 -workers=8
```

- First positional directory is the **output** corpus (new inputs saved
  there); further dirs are read-only seed sources. A positional *file*
  instead = replay that input once and exit (crash reproduction).
- `-max_len=N` max input size (0 = guess from corpus);
  `-len_control=0` to disable gradual length growth.
- `-jobs=N` run N fuzzing jobs (restarting on crash, logs to
  `fuzz-<job>.log`); `-workers=M` processes in parallel. `-fork=N` is the
  newer in-one-process parallel/crash-resistant mode.
- `-dict=dict.txt` AFL-format dictionary; `-seed=1` fixed RNG;
  `-runs=N` bounded run count; `-max_total_time=secs`.
- `-timeout=25` per-input seconds; `-rss_limit_mb=2048` (0 = off);
  `-malloc_limit_mb` single-allocation cap.
- `-only_ascii=1`, `-ignore_crashes=1` (with fork mode), `-artifact_prefix=dir/`
  where crash files go.
- `-print_final_stats=1`, `-print_coverage=1` (coverage dump at exit).

Env: `ASAN_OPTIONS=...`, and `LLVMFuzzerTestOneInput`-level repro is just
`./fuzz crash-file`.

## Artifacts and output

- Crashes: `crash-<sha1-of-input>`; also `leak-*`, `oom-*`, `timeout-*` in
  the CWD or `-artifact_prefix`.
- Console lines: `#2097152 pulse  cov: 1337 ft: 2718 corp: 412/88Kb exec/s: 65536`
  — `cov` = covered PCs/edges, `ft` = features (finer-grained), `corp` =
  corpus entries/bytes. `NEW` lines = new coverage saved; `REDUCE` = smaller
  equivalent found. A `DEDUP_TOKEN` and the ASan report follow a crash.

## Corpus management

- Minimize/merge: `./fuzz -merge=1 corpus_min/ corpus/ more_seeds/`
  (writes a coverage-minimal superset into the first dir). `-merge_control_file`
  resumes interrupted merges.
- Crash minimization: `./fuzz -minimize_crash=1 -runs=100000 crash-file`
  (iterates, leaves `minimized-from-*` artifacts; the last/smallest one is
  your reproducer).
- Cleanse: `./fuzz -cleanse_crash=1 crash-file` replaces irrelevant bytes
  with spaces — good for spotting the actually-meaningful bytes.

## Coverage inspection

Build a second binary with `-fprofile-instr-generate -fcoverage-mapping`
(no `-fsanitize=fuzzer`, add a `main` that calls the harness per file), run
it over the corpus, then `llvm-profdata merge` + `llvm-cov show` to see
which lines the campaign reaches. Unreached parser branches = dictionary or
CmpLog work, or a deeper harness.

## When to pick libFuzzer

- Fast single-binary iteration while developing the harness (seconds to
  build/run, crash repro is trivial).
- Then take the *same source* to AFL++ (`afl-clang-fast -fsanitize=fuzzer`)
  for CmpLog + schedules, and honggfuzz (`hfuzz-cc`) for threaded HW
  feedback — run all three against a shared corpus via AFL++ `-F` /
  periodic copy.
