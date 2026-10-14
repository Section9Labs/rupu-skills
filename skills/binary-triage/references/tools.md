# Tool reference — binary triage

Raw output of every command belongs in the evidence directory. Pipe through
`tee evidence/<tool>.<target>.txt`.

## file

```
file ./target             # one-line identification
file -b ./target          # brief: no leading filename (easier to parse)
file -k ./target          # keep going: report every match, not just the first
file -z ./target          # look inside compressed data
file -L ./target          # follow symlinks
file -i ./target          # MIME type (application/x-executable, x-sharedlib, x-pie-executable)
```

Decoding the ELF line:

```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=..., not stripped
```

- `pie executable` → ET_DYN with an interpreter (PIE). `shared object` with no
  interpreter → library. Plain `executable` → ET_EXEC, fixed load address.
- `interpreter /lib64/ld-…` → the dynamic loader path; absent on static bins.
- `for GNU/Linux 3.2.0` → minimum kernel ABI; hints at build era.
- `BuildID` → match against debug symbol servers and other samples.
- `MSB` instead of `LSB` → big-endian (MIPS/PowerPC firmware).

PE: `PE32 executable (console) Intel 80386` vs `PE32+ … x86-64`; `(DLL)` vs
`(console)`/`(GUI)`. Mach-O: `Mach-O 64-bit executable arm64`, or
`Mach-O universal binary with 2 architectures` → use `lipo`/`rabin2 -A` to
pick a slice.

`-k` on firmware images typically appends `\012- data` or a second match like
`gzip compressed data` after the ELF header — that trailing payload is a
separate carving task.

## strings

```
strings -a -n 8 ./target        # -a: whole file, every section (default on modern
                                #     binutils, but be explicit — older versions only
                                #     scanned initialized data)
strings -a -n 6 ./target        # lower threshold when 8 yields too little
strings -a -e l -n 8 ./target   # 16-bit little-endian (UTF-16LE): PE resources,
                                #     Windows registry paths, firmware UI strings
strings -a -e b ./target        # 16-bit big-endian
strings -a -e L / -e B          # 32-bit little/big endian literals
strings -a -t x ./target        # prefix each string with hex FILE offset
strings -a -t d ./target        # decimal offsets
```

File offset → virtual address for xref hunting: for each PT_LOAD in
`readelf -l`, if `p_offset <= off < p_offset + p_filesz` then
`vaddr = p_vaddr + (off - p_offset)`. Or let radare2 do it:
`rabin2 -z` prints both paddr and vaddr per string, and `rabin2 -zz` scans the
whole file like `strings -a`.

## nm

```
nm ./target                    # .symtab; "nm: ./target: no symbols" = stripped
nm -D ./target                 # .dynsym — present on any dynamically linked bin
nm -D --undefined-only ./tgt   # imports only (also: -u)
nm -D --defined-only ./tgt     # exports only — the API of a .so
nm -C ./target                 # demangle C++ (_ZN4...)
nm -S --size-sort ./target     # sizes; big functions = parsers = bug farms
nm -n ./target                 # sort by address, see layout
```

Symbol type letters: `T/t` text, `D/d` data, `B/b` bss, `R/r` rodata,
`U` undefined (import), `W/w` weak, `i` ifunc. Uppercase = global.
`@GLIBC_2.x` suffixes give you the exact symbol version — useful for picking
the matching libc build for ret2libc offsets.

## readelf

```
readelf -h ./target        # ELF header: Class (32/64), Machine, Type (EXEC/DYN/REL/CORE), Entry
readelf -l ./target        # program headers / segments
readelf -lW ./target       # -W/--wide: don't truncate columns (always use for parsing)
readelf -S ./target        # section headers
readelf -d ./target        # .dynamic: NEEDED, SONAME, RPATH, RUNPATH, FLAGS, FLAGS_1
readelf -r ./target        # relocations: R_X86_64_JUMP_SLOT = GOT/PLT entries
readelf -s ./target        # all symbol tables;  --dyn-syms for .dynsym only
readelf -x .rodata ./tgt   # hex-dump a section;  -p .comment for strings in it
readelf -n ./target        # notes: BuildID, GNU property (IBT/SHSTK flags!)
readelf -V ./target        # symbol version info
```

Key program headers:

- `INTERP` — presence distinguishes PIE executable from plain shared object.
- `GNU_STACK` — flags `RW ` = NX on; `RWE` = executable stack, NX off.
- `GNU_RELRO` — the segment remapped read-only after relocation; present =
  at least partial RELRO.
- `GNU_PROPERTY` — holds `x86 feature: IBT, SHSTK` (CET) markers, dumped by
  `readelf -n`.

Key `.dynamic` tags: `NEEDED` (dependency list — your attack transitively
includes those libraries), `BIND_NOW` or `FLAGS: BIND_NOW` or
`FLAGS_1: NOW` (eager binding → combined with GNU_RELRO = **full RELRO**),
`RPATH`/`RUNPATH` (library search override; RUNPATH is overridable by
`LD_LIBRARY_PATH`, RPATH is not), `DEBUG`, `INIT_ARRAY`/`FINI_ARRAY`
(function-pointer arrays — classic overwrite targets when writable).

## objdump

```
objdump -x ./target              # all headers + symbols + relocs, one shot; parses PE too
objdump -d -M intel ./target     # disassemble executable sections, Intel syntax
objdump -D -M intel ./target     # disassemble ALL sections (catches code hidden in data)
objdump -d -j .text ./target     # restrict to a section
objdump -d --disassemble=main    # one function (binutils >= 2.32)
objdump -s -j .rodata ./target   # raw hex dump of a section
objdump -R ./target              # dynamic relocations (the GOT, PE-compatible via -x)
objdump -T ./target              # dynamic symbol table (like nm -D)
objdump --start-address=0x401000 --stop-address=0x401100 -d ./target
```

For ARM: `-M force-thumb` when `file` says Thumb; for x86, `-M intel` always
(AT&T operand order has killed more exploits than ASLR).

## rabin2 (radare2)

Cross-format: ELF, PE, Mach-O, dex, raw. The triage workhorse when the sample
is not ELF.

```
rabin2 -I ./target        # info: arch, bits, endian, canary, nx, pic, relro,
                          #       stripped, static, lang, os — one shot
rabin2 -Ij ./target       # same as JSON (what scripts/triage.py consumes)
rabin2 -i ./target        # imports (PE IAT, ELF PLT, Mach-O lazy stubs)
rabin2 -s ./target        # symbols with vaddr/paddr
rabin2 -z ./target        # strings from data sections, with vaddr
rabin2 -zz ./target       # strings from the WHOLE file
rabin2 -e ./target        # entrypoints
rabin2 -l ./target        # linked libraries
rabin2 -R ./target        # relocations
rabin2 -O h ./target      # header fields; -H full header dump
rabin2 -A ./target        # list sub-binaries (fat Mach-O, firmware blobs)
rabin2 -x ./target        # extract sub-binaries to ./target.fat/
```

Every listing has a `j` JSON variant (`-ij`, `-zj`, `-sj`) — prefer those for
parsing. `rabin2 -I` fields `canary/nx/pic/relro` are the same facts checksec
reports; the `binary-protections` skill interprets them.

## checksec (preview — full treatment in `binary-protections`)

```
checksec --file=./target
checksec --output=json --file=./target
pwn checksec ./target          # pwntools' version, needs python3-pwntools
```
