---
name: binary-triage
description: First-contact triage of an unknown binary (ELF/PE/Mach-O/raw blob) — identify format/arch/linkage, mine strings and imports for attack surface, read ELF structure, and normalize results into rupu work units and assets. Use the moment a target binary lands, before any deep RE or exploitation work.
license: Proprietary
compatibility: Linux host with binutils (file, strings, nm, readelf, objdump); rabin2 (radare2) recommended for PE/Mach-O; checksec optional
metadata:
  author: Section9Labs
---

# Binary Triage

Goal: in minutes, know **what** the binary is, **what it reads** (attack
surface), **what looks dangerous**, and emit machine-readable work units so the
rest of the pipeline (`binary-protections`, `ghidra-headless`, `radare2`,
`pwntools`) can fan out.

Preserve everything: hash the sample first, keep every raw tool output under
the run workspace as evidence, never overwrite or delete it.

```
sha256sum ./target | tee evidence/sha256.txt
cp --preserve=all ./target evidence/target.orig
```

## 1. Identify

```
file ./target
file -k ./target        # keep going: report ALL matches, not just the first
```

Read the output left to right:

- **Format**: `ELF 64-bit LSB`, `PE32+ executable`, `Mach-O 64-bit`, or just
  `data` (raw blob → carve with `binwalk`, or it is a custom format).
- **Arch/bits**: `x86-64`, `Intel 80386`, `ARM aarch64`, `MIPS` — decides your
  disassembler flags and later your ROP calling convention.
- **`pie executable` vs `executable`** on ELF: DYN (PIE) vs EXEC (fixed base).
- **`statically linked` vs `dynamically linked`**: static means no GOT/PLT to
  attack but the whole libc's gadgets are inside the binary; dynamic means
  `nm -D` and GOT games still work after stripping.
- **`stripped` / `not stripped`**: whether `.symtab` survives. Dynamic symbols
  always survive stripping.
- **`-k` matters** for firmware: an ELF loader stub with a squashfs or gzip
  appended shows up only with keep-going. If `file -k` reports trailing data,
  load the `binwalk-firmware` skill to carve it before continuing.

Cross-format one-shot (works on PE and Mach-O too):

```
rabin2 -I ./target      # arch, bits, canary, nx, pic, relro, stripped, static
```

## 2. Strings — the cheapest intel you will ever get

```
strings -a -n 8 ./target                 # -a: scan ALL sections, not just loaded data
strings -a -e l -n 8 ./target            # UTF-16LE — mandatory on PE and common in firmware
strings -a -t x -n 8 ./target            # print hex file offsets, for xref hunting later
```

Hunt (grep the saved output, don't eyeball 50k lines):

| Pattern | Why it matters |
|---|---|
| `password`, `passwd`, `secret`, `api_key`, `token`, `PRIVATE KEY` | hardcoded credentials — instant findings |
| `http://`, `https://`, dotted-quad IPs | C2 of the vendor, update servers, internal hosts, SSRF pivots |
| `%n` anywhere, `%s` in error/log templates | format-string sinks — note the offset (`-t x`) and xref it in r2/Ghidra |
| `SELECT`/`INSERT ... %s` or `'` concat | SQL built by sprintf → injection |
| `/bin/sh -c %s`, `sh -c`, backtick/pipe templates | command injection sinks via `system`/`popen` |
| `GCC: (…)`, `OpenSSL 1.…`, `libcurl/…`, glibc banners | exact library versions → CVE lookup; feed glibc banners to the `libc-identification` skill |
| `/home/dev/project/foo.c`, `/build/...` | debug paths leak internal function/file names on a stripped binary |

The hex-offset form chains directly into radare2: `r2 -q -c 'axt @ <vaddr>'`
finds who references the string (load the `radare2` skill).

## 3. Symbols and imports

```
nm ./target                      # full symtab (empty if stripped: "no symbols")
nm -D ./target                   # dynamic symbols — survive stripping
nm -D --undefined-only ./target  # ONLY the imports: the libc functions it calls
nm -C ./target                   # demangle C++ names
rabin2 -i ./target               # imports, cross-format (PE IAT, Mach-O stubs)
rabin2 -s ./target               # symbols with vaddr — feed binary:symbol assets
```

In `nm` output: `U` = undefined (imported), `T`/`t` = text (functions),
`D/B` = data/bss. `name@GLIBC_2.2.5` version tags tell you the minimum glibc.

Red-flag imports — every one of these goes in the report and steers the next
phase:

| Import | Meaning for exploitation |
|---|---|
| `gets` | unbounded stdin read; guaranteed stack overflow, go straight to pwntools |
| `strcpy` `strcat` `sprintf` `vsprintf` | no bounds check; overflow wherever source is tainted |
| `scanf`/`sscanf`/`fscanf` | `%s`/`%[` without a width = overflow; check format strings from step 2 |
| `system` `popen` `exec*` | command execution; tainted argument = injection; also your ret2libc target |
| `memcpy` `strncpy` | fine *iff* the length is right — audit every length argument in the disasm |
| `printf` family, `syslog` | format string vuln when arg1 is user data; look for `printf(buf)` call sites |
| `malloc` `free` `realloc` | heap present → UAF / double-free / overflow class is in play |
| `setuid` `setgid` `seteuid` | privilege transitions; check drop order and unchecked return values |
| `dlopen` | runtime loading; tainted path or RPATH = library planting |
| `rand` `srand` | non-crypto PRNG; `srand(time(NULL))` tokens are predictable |

Then map imports → input sources (argv / stdin / files / network / env):
`recv`/`accept`/`socket` = network daemon; `fgets`/`read(0,…)`/`scanf` = stdin;
`fopen`/`open` = file parser; `getenv` = environment; `getopt` = argv. Full
mapping with confirmation steps: `references/attack-surface.md`.

## 4. ELF structure

```
readelf -h ./target   # Type: EXEC = no PIE, DYN = PIE or .so; Entry point
readelf -l ./target   # program headers: GNU_STACK flags RWE = NX OFF; GNU_RELRO present?
readelf -d ./target   # NEEDED libs; BIND_NOW/FLAGS_1 NOW = full RELRO; RPATH/RUNPATH = hijack candidate
readelf -S ./target   # sections: .plt/.got/.init_array/.tm_clone... write targets
readelf -r ./target   # relocations: JUMP_SLOT entries = the GOT you may overwrite
objdump -x ./target   # one-shot headers+symbols+relocs; also parses PE
```

Quick reads: `GNU_STACK` with `RWE` means shellcode on the stack is live.
`GNU_RELRO` + `BIND_NOW` means the GOT is read-only. `RPATH`/`RUNPATH`
pointing at a writable or relative directory is a privilege-escalation
primitive by itself. Flag details: `references/tools.md`.

## 5. Quick disassembly sanity pass

```
objdump -d -M intel ./target | less
objdump -d -M intel --disassemble=main ./target   # single function (binutils >= 2.32)
```

You are not reversing yet — you are confirming: real code vs packed garbage
(a tiny `.text` plus high-entropy sections = packer; check `rabin2 -I` entropy
and UPX banners from strings), the call style, and whether the dangerous
imports from step 3 are actually called (`grep 'call.*<gets@plt>'`).

## 6. Run the consolidated script

```
python3 scripts/triage.py ./target ./other-binary \
    -o work-units.json --evidence-dir evidence/
```

It shells out to `file`, `strings`, `nm`, `readelf`, `objdump`, `rabin2`, and
`checksec` (skipping any that are missing), prints a human report with a
protections summary and a flagged-dangerous-imports table, saves raw outputs
under `--evidence-dir`, and writes a **rupu work-units JSON array** — one unit
per binary:

```json
[{
  "id": "target-3f1a9b2c",
  "title": "Triage follow-up: target (ELF x86-64 64-bit)",
  "targets": [{
    "file": "/work/target", "sha256": "3f1a9b2c…", "format": "elf",
    "arch": "x86-64", "bits": 64, "pie": true, "stripped": true,
    "dangerous_imports": ["gets", "printf", "system"]
  }],
  "hints": ["binary-protections", "ghidra-headless", "radare2"]
}]
```

## 7. Record assets and hand off

Mark each live binary with rupu at depth `triaged` (ladder:
discovered → triaged → analyzed → vuln-identified → exploited, monotonic):

```
assets.mark  kind=binary:file  coords=[{t: file, v: <sha256>}]  depth=triaged
             note="target: ELF x86-64 PIE, dynamic, stripped; imports gets/system; net surface"
```

Mark notable sinks as `binary:symbol` (file coord + `{t: symbol, v: gets}` or
`{t: vaddr, v: 0x401a30}`) at `discovered`. Full wiring, the `work-units`
fan-out and the `finding-report` contract: `references/rupu.md`.

Hand off:

- **`binary-protections`** — the mitigation read (NX/canary/PIE/RELRO/FORTIFY)
  and what it does to the exploitation plan. Always next.
- **`ghidra-headless`** / **`radare2`** — deep static RE of the flagged call
  sites and string xrefs.
- **`fuzzing`** — when the surface is a file/protocol parser rather than a
  single obvious sink.
- **`pwntools`** — once a concrete sink (e.g. `gets`) is confirmed reachable.

## References

- `references/tools.md` — deep flag reference: file, strings, nm, readelf, objdump, rabin2.
- `references/attack-surface.md` — imports/strings → input-source mapping and confirmation tricks.
- `references/rupu.md` — work-units shape, `assets.mark` model, findings wiring.
