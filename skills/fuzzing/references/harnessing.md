# Harnessing, corpora, and dictionaries

## Picking the harness point

Order of preference:

1. **A pure parse/decode function** `f(buf, len)` — ideal: deterministic,
   fast, no I/O. Find it by reading headers or, for a binary-only target,
   by locating the function that first touches file bytes (use the
   `ghidra-headless` / `radare2` sibling skills: xrefs from `read`/`fread`
   /`recv` into the parsing cluster).
2. **An API sequence** — init/parse/use/free. Encode the sequence in the
   harness; derive variability from the input bytes (see consuming below).
3. **The whole program** — argv/stdin/file via AFL++ `@@`, QEMU `-Q` /
   FRIDA `-O` when there's no source. Network daemons: preload a
   desocketing shim (preeny `desock.so` via `AFL_PRELOAD`) so the socket
   reads come from stdin.

## Harness quality rules

- **Deterministic**: same bytes → same path. Kill `rand()` (seed it
  constant), time checks, PID-dependent behavior. AFL++ "stability" < 90%
  tells you that you failed.
- **No leaks**: free everything per iteration or ASan/LSan noise drowns
  real bugs and persistent mode OOMs. If the library leaks internally,
  `ASAN_OPTIONS=detect_leaks=0` for the campaign, LSan pass separately.
- **No exit()**: a target calling `exit()` on bad input looks like a normal
  finish, hiding paths. Stub it or patch the checker.
- **Checksums/CRCs**: patch them out in the fuzz build (`#ifdef FUZZING`
  — the convention `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` exists for
  this) or let CmpLog solve them (works for simple ones).
- **Reject early, cheaply**: `if (size < MIN) return 0;` — don't let the
  corpus fill with useless tiny inputs.

## Consuming structured input

Split the byte stream into fields manually, or use the
FuzzedDataProvider idiom (header-only, ships with LLVM):

```cpp
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int mode   = fdp.ConsumeIntegralInRange<int>(0, 3);
    auto flags = fdp.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> body = fdp.ConsumeRemainingBytes<uint8_t>();
    target_process(mode, flags, body.data(), body.size());
    return 0;
}
```

For API-sequence fuzzing, read an opcode byte in a loop and dispatch to
one API call per opcode — this is how heap-manager and interpreter bugs
are found (and feeds `heap-exploitation` directly when it hits).

## Persistent mode details

AFL++ source persistent mode:

```c
__AFL_FUZZ_INIT();
int main(void) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();          // place AFTER one-time setup, BEFORE the loop
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    reset_global_state();          // mandatory if the target keeps state
    target(buf, len);
  }
  return 0;
}
```

- `__AFL_LOOP(N)`: N iterations per process, then re-fork — a state-leak
  safety valve. 10000 is fine for clean targets; drop to 100–1000 if
  stability degrades.
- Compiles to a normal binary without AFL++ too (the macros become a
  read-stdin-once loop), so one source serves debugging and fuzzing.

honggfuzz: `HF_ITER(&buf, &len)` in an infinite loop, or just compile the
libFuzzer harness with `hfuzz-cc`. libFuzzer: always persistent by design.

## Seed corpus

- Collect real inputs: test suites of the project, protocol captures,
  sample files. 10–500 small (<4KB where possible) diverse files beat one
  huge pile.
- Minimize before the campaign:
  - AFL++: `afl-cmin -i raw_seeds -o corpus -- ./target @@` then
    `for f in corpus/*; do afl-tmin -i $f -o $f.min -- ./target @@; done`
  - libFuzzer: `./fuzz -merge=1 corpus/ raw_seeds/`
  - honggfuzz: `honggfuzz -i raw_seeds -M -- ./target ___FILE___`
- An empty-but-valid minimal file of the format is the single best seed.

## Dictionaries

AFL dictionary format (shared by AFL++, libFuzzer `-dict=`, honggfuzz `-w`):

```
# png.dict
header="\x89PNG\x0d\x0a\x1a\x0a"
sect_ihdr="IHDR"
sect_idat="IDAT"
```

Sources, best first:

1. `AFL_LLVM_DICT2FILE=/abs/dict.txt` at `afl-clang-lto` build time —
   extracts every compared constant automatically.
2. CmpLog (`-c`) — not a dictionary but solves the same problem at run time.
3. AFL++ `dictionaries/` directory — prebuilt dicts for common formats.
4. Hand-written from the spec/RE: magic numbers, chunk tags, keywords,
   length-field edge values (`\x00\x00`, `\xff\xff\xff\xff`, `\x7f\xff\xff\xff`).

AFL++ also auto-extracts tokens during the run (autodict with LTO builds)
and `-x` can be given multiple times.

## Scaling and campaign hygiene

- One CPU core per fuzzer instance; `afl-fuzz` pins cores automatically.
- Rotate: when `last new find` exceeds hours — add seeds from the other
  engines' corpora, re-minimize (`afl-cmin`), swap schedules (`-p rare`),
  check coverage (`afl-showmap` / `llvm-cov`) for walls (checksum? length
  check? unimplemented feature flag?) and re-harness past them.
- Keep `out/` forever: `queue/` is a reusable corpus for the next version
  of the target; `plot_data`/`fuzzer_stats` is evidence of effort/coverage.
