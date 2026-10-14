# Running a binary against a provided libc

When the target ships its own `libc.so.6` (CTF handout, firmware rootfs,
container image you pulled from the engagement), run and debug the binary
against THAT libc locally — allocator behavior (`heap-exploitation`) and
offsets must match the remote.

## Why plain LD_PRELOAD often fails

```bash
LD_PRELOAD=./libc.so.6 ./target
```

works only when your system loader (`/lib64/ld-linux-x86-64.so.2`) is
version-compatible with the preloaded libc. glibc and its `ld.so` are a
matched pair; a 2.27 libc under a 2.35 loader typically dies with
`version GLIBC_PRIVATE not found` or segfaults in `_dl_*`. You need the
matching loader — get it with libc-database `./download <id>`, from the same
rootfs, or from the distro package.

## Correct: run under the matching loader explicitly

```bash
./ld-2.27.so --library-path . ./target
# or with the libc preloaded by absolute path:
./ld-2.27.so --preload ./libc.so.6 ./target
```

Downside: argv[0]/auxv differ slightly and gdb attach needs care. Preferred
for permanent setups: patchelf.

## patchelf — rewrite the binary's interpreter and DT_NEEDED

```bash
cp target target.patched
patchelf --set-interpreter ./ld-2.27.so target.patched
patchelf --replace-needed libc.so.6 ./libc.so.6 target.patched
# optional, keeps lookups relative to the binary:
patchelf --set-rpath . target.patched
./target.patched            # now runs against the shipped libc everywhere
```

Notes:
- Use relative or absolute paths consistently; `--set-rpath '$ORIGIN'` makes
  the patched binary portable within its directory.
- patchelf changes the file hash — keep the pristine original for offsets
  and for the final remote exploit; the patched copy is only a local test
  harness. Record both hashes as assets (references/rupu.md).
- `pwninit` (https://github.com/io12/pwninit) automates all of this: drops
  the matching `ld.so` for a given libc, patches the binary, and unstrips
  the libc's debug symbols from debuginfod — unstripped libc makes pwndbg's
  `heap`/`bins` commands fully symbolic.

## Debug symbols

Stripped shipped libcs hide `main_arena` etc. Restore them:

```bash
# pwninit does this automatically; manually:
eu-unstrip ./libc.so.6 /usr/lib/debug/.build-id/xx/<buildid>.debug  # if you have the .debug
# or fetch via debuginfod:
DEBUGINFOD_URLS="https://debuginfod.elfutils.org/" gdb ./target.patched
```

## pwntools integration

```python
from pwn import *
elf  = context.binary = ELF('./target')          # pristine, for GOT/PLT offsets
libc = ELF('./libc.so.6')
p = process('./target.patched')                   # local, correct allocator
# ... leak ...
libc.address = leak - libc.symbols['puts']
```

Load the `pwntools` skill for process/remote tubes, `gdb.attach`, and ROP
helpers; load `gdb-debugging` for the pwndbg heap-inspection workflow.
