# AFL++ reference

AFL++ (https://aflplus.plus) is the maintained successor of AFL: better
instrumentation (LLVM PCGUARD/LTO), input-to-state (CmpLog/redqueen),
custom mutators, QEMU/FRIDA/Unicorn/Nyx modes.

## Compilers

| Wrapper | Use when |
|---|---|
| `afl-clang-lto` / `afl-clang-lto++` | clang ≥ 11 with LLD. Best: collision-free instrumentation, `AFL_LLVM_DICT2FILE`, autodict. |
| `afl-clang-fast` / `afl-clang-fast++` | Default LLVM mode (PCGUARD). Supports all `AFL_LLVM_*` passes. |
| `afl-gcc-fast` / `afl-g++-fast` | GCC plugin, when the code only builds with gcc. |
| `afl-cc` / `afl-c++` | Meta-wrapper; select mode via `AFL_CC_COMPILER=LTO|LLVM|GCC_PLUGIN`. |

Typical autotools/CMake build:

```sh
export CC=afl-clang-lto CXX=afl-clang-lto++
export AFL_USE_ASAN=1            # or UBSAN/MSAN/CFISAN/TSAN/LSAN (one per build)
./configure --disable-shared && make -j$(nproc)
# cmake: cmake -DCMAKE_C_COMPILER=afl-clang-lto .. && make
```

Build matrix for a serious campaign (same source, different env):

```sh
make                                   # 1. plain fast binary        -> most -S nodes
AFL_USE_ASAN=1 make                    # 2. ASan binary              -> one -S node + all triage
AFL_LLVM_CMPLOG=1 make; cp target target.cmplog   # 3. CmpLog binary -> -c on 1-2 nodes
AFL_LLVM_LAF_ALL=1 make                # 4. laf-intel split-compare  -> 1-2 -S nodes
```

Useful build-time env:

- `AFL_LLVM_CMPLOG=1` — build the CmpLog (redqueen) binary; pass it at run
  time with `-c ./target.cmplog`. Solves magic bytes/checksums by copying
  observed comparison operands into the input ("input-to-state").
- `AFL_LLVM_LAF_ALL=1` — split all comparisons into byte-wise chains
  (equivalent to `AFL_LLVM_LAF_SPLIT_SWITCHES/COMPARES/FLOATS` +
  `TRANSFORM_COMPARES` for str/memcmp). Lets plain coverage walk through
  32/64-bit compares one byte at a time.
- `AFL_LLVM_DICT2FILE=/abs/dict.txt` (`afl-clang-lto`) — dump all string/int
  comparison operands as a dictionary at compile time.
- `AFL_LLVM_ALLOWLIST=/path/list.txt` / `AFL_LLVM_DENYLIST` — instrument only
  some files/functions (focus the map).
- `AFL_HARDEN=1` — fortify + stack protector for non-ASan builds (catches
  some corruptions cheaply).
- `AFL_INST_RATIO=100` — instrumentation density (lower for enormous targets).

## Harness forms

1. **File/stdin program**: fuzz the real binary; `@@` for file arg, nothing
   for stdin.
2. **Persistent mode** (fastest, in `afl-clang-fast/lto` compiled source):

```c
__AFL_FUZZ_INIT();
int main(void) {
  #ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();                           // forkserver starts HERE, after heavy setup
  #endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be read after __AFL_INIT
  while (__AFL_LOOP(10000)) {             // iterations before re-fork (state hygiene)
    int len = __AFL_FUZZ_TESTCASE_LEN;    // re-read every iteration
    if (len < 4) continue;
    target_parse(buf, len);
  }
  return 0;
}
```

   `__AFL_FUZZ_TESTCASE_BUF` is shared memory — no file/stdin syscalls at all.
   Lower the `__AFL_LOOP` count if the target leaks state between iterations.
3. **libFuzzer harness**: `afl-clang-fast -fsanitize=fuzzer harness.c lib.a -o target`
   links AFL++'s libFuzzer shim; run the result like any AFL++ target (it
   reads stdin by default; persistent + sharedmem automatically).

## afl-fuzz run reference

```sh
afl-fuzz -i corpus -o out [opts] -- ./target [args] @@
```

- `-i dir` seeds (`-i -` to resume from `out/<name>`); `-o dir` sync dir.
- `@@` substituted with testcase path; absent → stdin.
- `-x dict.txt` dictionary (repeatable); `-c ./target.cmplog` CmpLog binary
  (`-l 2AT` tunes CmpLog intensity/transforms).
- `-t ms` exec timeout (`-t 2000+` = skip hanging seeds instead of aborting);
  `-m megs|none` memory limit — **`-m none` for ASan**.
- `-M name` single main node (deterministic stages, syncs all);
  `-S name` secondaries (havoc only). All share `-o out`; each writes
  `out/<name>/{queue,crashes,hangs,fuzzer_stats,plot_data}`.
- `-p fast|coe|explore|lin|quad|exploit|mmopt|rare|seek` power schedule
  (default `explore`; `fast` is the common pick; `rare` chases rare edges).
- `-D` enable deterministic mutation stages on this node (off by default,
  run on exactly one node); `-L minutes` MOpt mutator.
- `-Q` QEMU mode (black-box ELF, no recompile; env `AFL_QEMU_PERSISTENT_ADDR`
  for persistent-mode-at-an-address); `-O` FRIDA mode (same idea,
  Frida-based, works where QEMU doesn't); `-U` Unicorn; `-W` wine.
- `-V seconds` stop after fixed time; `-F dir` sync from a foreign fuzzer's
  queue (e.g. honggfuzz corpus) — the standard cross-fuzzer bridge.
- `-f file` write testcase to a fixed path (targets that insist on a name).
- Env: `AFL_AUTORESUME=1`, `AFL_FINAL_SYNC=1`, `AFL_TESTCACHE_SIZE=500`,
  `AFL_IMPORT_FIRST=1` (secondaries pull queue before fuzzing),
  `AFL_PRELOAD=./desock.so` (preload e.g. preeny's desock to turn a network
  server into a stdin target).

## Reading the status screen

- **process timing**: `last new find` growing to hours → plateau; feed new
  seeds, add a dictionary, add CmpLog, or re-harness deeper.
- **overall results**: `corpus count`, `saved crashes`, `saved hangs`.
- **cycle progress / stage**: cycle counter turns green when a full queue
  cycle found nothing new.
- **map coverage**: `map density` > ~70% means map collisions (use LTO);
  very low (<1%) means the harness barely reaches the target.
- **speed**: `exec speed` < 500/s per core is slow — persistent mode, smaller
  seeds, `-t` tuning. "slow" warning in red is a harness problem.
- **stability** < 90%: nondeterministic target (threads, RNG, uninit memory);
  find the cause with `AFL_DEBUG=1` or accept reduced efficiency.
- `afl-whatsup -s out/` — fleet summary; `afl-plot out/main graphdir` —
  gnuplot progress graphs.

## Companion tools

- `afl-cmin -i seeds -o corpus -- ./target @@` — corpus minimization by
  coverage (keep the smallest set with the same edges). `-T all` parallel.
- `afl-tmin -i crash -o crash.min -- ./target @@` — testcase minimization
  (crash kept crashing / path kept identical). Use the ASan binary with
  `-m none -t 2000`.
- `afl-showmap -o map.txt -- ./target @@ <in` — dump the coverage map for
  one input; `-C` collect from a dir. Good for "does my seed even reach X".
- `afl-analyze -i testcase -- ./target @@` — byte-level structure guess.
- `afl-system-config` — set the host perf knobs (core_pattern, governor);
  without it afl-fuzz aborts unless `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`
  / `AFL_SKIP_CPUFREQ=1`.

## Crash output layout

`out/<node>/crashes/id:000000,sig:11,src:000031,time:...,op:havoc,rep:4`
— the `sig:` is the killing signal. `README.txt` in the dir records the
command line. Hangs are in `out/<node>/hangs/`. `fuzzer_stats` is key:value
(parse `saved_crashes`, `execs_per_sec`, `corpus_count`).

## Campaign recipe (16 cores, library target)

```sh
afl-system-config
afl-fuzz -i corpus -o out -M main -D -x dict.txt -- ./target @@ &
afl-fuzz -i corpus -o out -S cmplog1 -c ./target.cmplog -l 2AT -- ./target @@ &
afl-fuzz -i corpus -o out -S asan1 -m none -- ./target_asan @@ &
afl-fuzz -i corpus -o out -S laf1 -- ./target_laf @@ &
for i in $(seq -w 4 15); do
  afl-fuzz -i corpus -o out -S s$i -p fast -- ./target @@ &
done
watch afl-whatsup -s out
```
