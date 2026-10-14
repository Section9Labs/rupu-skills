---
name: binwalk-firmware
description: Carve, extract, and triage firmware images and unknown binary blobs with binwalk — signature/entropy/opcode scans, recursive (Matryoshka) extraction, filesystem unpacking (SquashFS/JFFS2/UBIFS/cpio and friends), then rootfs triage for network daemons, setuid binaries, hardcoded credentials and CVE-bearing component versions — emitting rupu work units that fan out to binary-triage and qiling-unicorn. Use whenever you are handed a firmware.bin, OTA update, flash dump, or any unknown blob that must be opened before real analysis can start.
license: Apache-2.0
metadata:
  author: Section9Labs
---

# binwalk-firmware — carve, extract, and triage firmware images

Goal: turn an opaque `firmware.bin` into an extracted root filesystem plus a
prioritized list of binaries to attack, each handed off as a rupu work unit to
the `binary-triage` / `qiling-unicorn` skills.

Pipeline: **identify → carve/extract → locate rootfs → triage → fan out**.
Keep every raw binwalk log and every carved blob under the run workspace as
evidence — never delete intermediate output.

## 0. Know your binwalk: v2 (Python) vs v3 (Rust)

Check first: `binwalk --help | head -1`. v3 prints `Binwalk v3.x`.

| Task                | v2 (Python)                  | v3 (Rust rewrite)                |
|---------------------|------------------------------|----------------------------------|
| Signature scan      | `binwalk fw.bin` (`-B`)      | `binwalk fw.bin`                 |
| Entropy             | `-E` (needs matplotlib)      | `-E` (terminal plot, no deps)    |
| Opcode/arch scan    | `-A` (`--opcodes`)           | removed — use `-Y` or disasm     |
| Capstone arch guess | `-Y` (`--disasm`)            | not in v3 — use v2 or cpu_rec    |
| Extract             | `-e`                         | `-e`                             |
| Recursive extract   | `-M -e`                      | `-M -e` (v3 also has `-e` depth) |
| Raw carve           | `--dd='.*'`                  | `--carve` (carves every hit)     |
| Output dir          | `-C DIR` / `--directory=DIR` | `-d DIR` / `--directory DIR`     |
| Log to file         | `-f file.log` / `--csv`      | `-l file.json` (JSON log)        |
| Byte swap / offsets | `-Z`, `-o`, `-l`, `-g`       | `-o/--offset`, `-L/--length`     |

Both default-extract into the **current working directory** (`_fw.bin.extracted/`
for v2, `extractions/` for v3) — `cd` into your evidence dir before `-e`.
Full flag tables: `references/binwalk.md`.

## 1. Identify and scan

```sh
file firmware.bin                      # sometimes already names it (uImage, TRX…)
binwalk firmware.bin                   # signature scan
binwalk -E firmware.bin                # entropy scan
binwalk -A firmware.bin                # v2: opcode scan on a raw blob
binwalk -Y firmware.bin                # v2: capstone disasm arch detection
```

Read the signature scan:
- **Bootloaders / headers**: `uImage header`, `U-Boot`, `TRX`, `CHK`, `DLOB`,
  device-tree blobs (`flattened device tree`). The header tells you load
  address, arch, and often the compression of the payload.
- **Kernels**: `LZMA compressed data` right after a uImage header is almost
  always the kernel. Note the reported dictionary size/uncompressed size —
  absurd values (e.g. 4 EiB) mean a false positive.
- **Filesystems**: `Squashfs filesystem`, `JFFS2`, `UBI image`/`UBIFS`,
  `CramFS`, `ASCII cpio archive`, `romfs`. The *last large filesystem* in the
  image is usually the root filesystem.
- **Compressed blobs**: gzip, LZMA, XZ, LZ4, zstd, bzip2 regions.
- **Certificates / keys**: `PEM certificate`, `PEM RSA private key`,
  `OpenSSH private key` — immediate findings, note the offsets.

Read the entropy scan (`-E`):
- ~0.3–0.9 wavy entropy → code/data, extractable.
- Flat line pinned at ~1.0 across the whole image → **encrypted or already
  compressed**; signature scan will be nearly empty. See §5.
- A **sharp step** in the plot marks a boundary: plaintext header/bootloader
  before, encrypted/compressed payload after. Record the step offset — that is
  where you carve (`dd if=fw.bin bs=1 skip=OFFSET of=payload.bin`) and where
  the decryption stub lives.

Arch of a headerless raw blob: `binwalk -A` (v2) counts function
prologue/epilogue opcode hits per architecture — the arch with hundreds of
consistent hits at sane alignment wins (MIPS/MIPSEL, ARM/ARM64, x86, PPC).
`binwalk -Y` (v2) uses capstone to confirm and reports endianness. Cross-check
with the ELF header of any extracted binary later.

## 2. Extract and carve

```sh
mkdir -p extracted && cd extracted
binwalk -e ../firmware.bin                 # run default extractors on known types
binwalk -M -e ../firmware.bin              # Matryoshka: recursively re-scan+extract
                                           # everything extracted (nested blobs)
binwalk --dd='.*' ../firmware.bin          # v2: carve EVERY signature hit raw
binwalk --carve ../firmware.bin            # v3 equivalent raw carve
```

Controlling the extractor set (v2):
- `--dd='<type-regex>:<ext>[:<command>]'` — carve matches of a signature
  description, e.g. `--dd='squashfs:squashfs'` or run a command on each carve:
  `--dd='zip archive:zip:unzip -o %e'` (`%e` = carved file path).
- `-D` is the same as `--dd`. `--dd='.*'` carves everything, no unpacking —
  your fallback when extractors choke.
- Extractor allowlist/denylist: v2 reads `extract.conf`; per-run you restrict
  with `-y <sig>` (only scan matching signatures) and `-x <sig>` (exclude),
  e.g. `binwalk -e -y 'squashfs' fw.bin` to extract only the squashfs and skip
  a false-positive LZMA that hangs. v3: `--include=<sig>` / `--exclude=<sig>`.
- `-j/--size` and `-n/--count` bound carve size/count; `-r` deletes carved
  files that extracted cleanly (don't — keep evidence).
- v2 run as root: add `--run-as=root` or binwalk refuses extraction.

If binwalk's bundled extractor fails on a filesystem, carve it raw
(`--dd`/`--carve` or `dd` at the reported offset) and unpack manually:

| Carved type        | Tool / command                                             |
|--------------------|------------------------------------------------------------|
| SquashFS           | `unsquashfs -d squashfs-root 1A2B3C.squashfs`              |
| SquashFS (vendor)  | `sasquatch -d squashfs-root blob.squashfs` (non-std LZMA)  |
| JFFS2              | `jefferson -d jffs2-root blob.jffs2`                       |
| UBI / UBIFS        | `ubireader_extract_files -o ubifs-root blob.ubi` / `ubidump.py` |
| CramFS             | `cramfsck -x cramfs-root blob.cramfs` / `7z x`             |
| cpio / initramfs   | `cpio -idmv --no-absolute-filenames < blob.cpio`           |
| romfs              | `7z x blob.romfs` or binwalk's romfs extractor             |
| gzip/xz/lzma/lz4/zstd | `gunzip`/`xz -d`/`lzma -d` (try `-lc1 -pb0` dicts)/`lz4 -d`/`zstd -d` |

`firmware-mod-kit` (`extract-firmware.sh fw.bin`) automates split+extract and
later **repacking** (`build-firmware.sh`) for backdooring/modification jobs;
it bundles `sasquatch` for the vendor-hacked SquashFS variants (DD-WRT,
Realtek, Broadcom). Per-filesystem detail and failure modes:
`references/filesystems.md`.

## 3. Locate the root filesystem

After `binwalk -Me`, look under `_firmware.bin.extracted/` (v2) or
`extractions/` (v3) for `squashfs-root/`, `cpio-root/`, `jffs2-root/`,
`ubifs-root/`, or any directory with `bin/busybox`, `etc/`, `sbin/init`,
`lib/libc*`. Multiple filesystems = rootfs + web partition + config/overlay;
triage all, but the one with `/sbin/init` or `/etc/inittab` is the rootfs.

## 4. Triage the rootfs

Full checklist in `references/rootfs-triage.md`. The short loop, from inside
`squashfs-root/`:

```sh
# What runs at boot → what is actually reachable
cat etc/inittab etc/rc.local; ls etc/init.d/; grep -r . etc/init.d/ | less
# Network daemons: the real attack surface
find . -type f -name '*httpd*' -o -name '*telnetd*' -o -name 'dropbear*' \
       -o -name 'upnpd*' -o -name 'dnsmasq' -o -name '*cgi*'
grep -rl --include='*' -e socket -e bind -e recv bin sbin usr/bin usr/sbin
ls -la www/ cgi-bin/ usr/www/ web/ 2>/dev/null       # web root + CGI binaries
cat etc/services 2>/dev/null
# Privilege escalation surface
find . -perm -4000 -type f -exec ls -la {} \;        # setuid
# Secrets
cat etc/passwd etc/shadow 2>/dev/null
grep -rn 'PRIVATE KEY' . ; find . -name '*.pem' -o -name '*_key*' -o -name '*.crt'
grep -rni 'password=' etc/ www/ --include='*.conf' --include='*.cfg' \
     --include='*.xml' --include='*.sh' 2>/dev/null
# Known-CVE component versions
strings bin/busybox | grep -i 'busybox v'
strings usr/sbin/dropbear 2>/dev/null | grep -iE 'dropbear.*20[0-9]{2}'
strings usr/sbin/lighttpd usr/sbin/uhttpd 2>/dev/null | grep -iE 'lighttpd/|uhttpd'
```

Prioritize: **(1)** daemons started by init that bind a socket (httpd, upnpd,
telnetd, custom vendor daemons), **(2)** CGI binaries under `www/cgi-bin`
(direct unauthenticated input), **(3)** setuid binaries, **(4)** anything with
hardcoded credentials nearby. Check each component version against known CVEs
(old BusyBox telnetd, Dropbear < 2016.74, lighttpd < 1.4.35, GoAhead,
Boa/mini_httpd are perennial).

## 5. Encrypted / obfuscated images

Flat ~8 bits/byte entropy and no signatures → encrypted (or vendor-obfuscated).
- Zoom the entropy map: a low-entropy region at the start is the plaintext
  header/loader — carve and disassemble it (`binwalk -A`/Ghidra); the
  decryption routine and the **XOR or AES key** live there or in the on-device
  bootloader.
- Hunt an **earlier unencrypted release** of the same firmware from the vendor
  portal: vendors typically ship the decryption logic in the last plaintext
  version (`imgdecrypt`, `encimg`, key material in `/etc/` or the upgrade
  binary). Extract that version, find the decrypt tool, run it (natively or
  via qemu-user) against the new image.
- Try trivial XOR first: a repeating pattern in the "encrypted" region's
  byte histogram = single/short-key XOR; recover the key by XORing against
  expected plaintext (0x00 runs, SquashFS magic `hsqs`).
- If no key path exists yet, **record it and stop**: mark the image asset as
  `discovered` with a note that extraction is blocked on key recovery
  (hardware dump of the bootloader, UART, or vendor-tool reversing), and emit
  no bogus work units.

## 6. Scripted triage and rupu handoff

```sh
python3 scripts/firmware_triage.py ./firmware.bin -o ./triage-out
python3 scripts/firmware_triage.py ./squashfs-root        # already extracted
```

The script runs the binwalk signature scan + extraction (or walks a directory
you already extracted), locates the rootfs, inventories ELF binaries (magic +
arch + endianness), setuid files, credential/key candidates, and component
version strings, prints the triage report, and writes
`triage-out/work-units.json` — a JSON array of
`{id, title, targets, hints}` units, one per high-value binary, suitable for a
rupu `for_each:` fan-out (see the shared `work-units` skill). It degrades to
directory-walk-only with printed guidance when `binwalk`/`unsquashfs` are
missing.

Wiring (details in `references/rupu.md`):
- `assets.mark` every extracted binary as `binary:file` at `discovered`
  (promote as sibling skills work them: triaged → analyzed → vuln-identified
  → exploited); carved rootfs and binwalk logs stay in the workspace as
  evidence.
- `findings.report` (shared `finding-report` skill) for hardcoded
  credentials/private keys and CVE-bearing component versions found here.
- Each work unit's `hints` names the next skill: `binary-triage` and
  `binary-protections` for static work, `qiling-unicorn` to emulate the
  daemon against the extracted rootfs (`Qiling(["squashfs-root/bin/httpd"],
  rootfs="squashfs-root")`), or raw qemu-user when you cannot run natively:

```sh
qemu-mipsel-static -L squashfs-root squashfs-root/bin/httpd      # dyn-linked
chroot squashfs-root /qemu-mipsel-static /bin/sh                 # full chroot
```

Match the qemu binary to the ELF header the script reports
(`qemu-mips-static` big-endian, `qemu-mipsel-static` little, `qemu-arm-static`,
`qemu-aarch64-static`). Load the `qiling-unicorn` skill for hooked/instrumented
emulation and the `binary-triage` skill for the per-binary deep dive.
