# Firmware filesystem & compression unpacking

Binwalk's `-e` handles most of these if the extractor binaries are installed.
When it leaves a raw carve behind (e.g. `1A2B3C.squashfs`), unpack manually.

## SquashFS (the common case)

Magic: `hsqs` (LE) / `sqsh` (BE); binwalk reports version + compression
(gzip, lzma, xz, lzo, lz4, zstd) and size.

```sh
unsquashfs -d squashfs-root 1A2B3C.squashfs
unsquashfs -s 1A2B3C.squashfs            # superblock info only (version/compression)
unsquashfs -ll 1A2B3C.squashfs           # list with perms/uids without extracting
```

Modern `squashfs-tools` must be built with every compressor
(`xz`, `lzo`, `lz4`, `zstd` dev libs) or it refuses the image.

**Vendor-hacked SquashFS** (DD-WRT, Broadcom, Realtek SDKs — non-standard
LZMA parameters, shifted magics like `shsq`/`qshs`, bogus version numbers):
use **sasquatch** (github.com/devttys0/sasquatch), a patched unsquashfs that
brute-forces LZMA variants:

```sh
sasquatch -d squashfs-root blob.squashfs
sasquatch -be ...        # force big-endian when auto-detect fails
```

**firmware-mod-kit** wraps split+extract+**repack** — essential when the goal
is modifying and reflashing:

```sh
./extract-firmware.sh firmware.bin workdir/   # → workdir/rootfs/, image_parts/
# edit workdir/rootfs/ ...
./build-firmware.sh workdir/                  # rebuilds flashable image, fixes checksums (TRX etc.)
```

Repack standard SquashFS yourself: `mksquashfs squashfs-root new.squashfs
-comp xz -b 131072 -noappend` — match the original block size and compression
reported by `unsquashfs -s`.

## JFFS2

Journaling flash FS; often on NOR flash, frequently the writable config
partition rather than the rootfs. Node-based: expect multiple versions of
files (deleted/old config — great for credential archaeology).

```sh
pip install jefferson
jefferson -d jffs2-root blob.jffs2
jefferson -d jffs2-root -v blob.jffs2    # verbose; shows endianness handling
```

Big-endian images from MIPS devices work out of the box; if output is garbage,
byte-swap first (`binwalk -g 2` or `jffs2dump -b -e`). Alternative: mount it
on Linux via `mtdram`:

```sh
modprobe mtdram total_size=65536 erase_size=128
dd if=blob.jffs2 of=/dev/mtdblock0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2
```

## UBI / UBIFS

Two layers: UBI (volume management over raw NAND) containing UBIFS volumes.
binwalk reports `UBI erase count header` repeatedly — that's one UBI image,
not hundreds of files.

```sh
pip install ubi_reader
ubireader_display_info blob.ubi                  # PEB size, volumes
ubireader_extract_images -o out/ blob.ubi        # pull UBIFS volume images
ubireader_extract_files  -o ubifs-root/ blob.ubi # extract files directly
# alternative: ubidump.py (github.com/nlitsme/ubidump)
python3 ubidump.py --savedir ubifs-root blob.ubi
```

If extraction misparses, pass the erase block size explicitly
(`-p 131072`, from the NAND datasheet or `ubireader_display_info`).

## CramFS

Read-only compressed FS, legacy devices. Magic `0x28cd3d45`.

```sh
cramfsck -x cramfs-root blob.cramfs      # from cramfsprogs / fsck.cramfs -x
7z x blob.cramfs -ocramfs-root           # 7-zip also reads it
# firmware-mod-kit ships uncramfs/uncramfs-lzma for vendor LZMA variants
```

Big-endian images may need `cramfsswap` first.

## cpio / initramfs

Kernel initramfs is a (often gzip/xz-compressed) `newc` cpio archive.

```sh
zcat blob.cpio.gz | cpio -idmv --no-absolute-filenames   # inside a fresh dir
xz -dc initramfs.xz | cpio -idmv --no-absolute-filenames
# concatenated archives (microcode prepended): skip with `cpio -idmv; cpio -idmv` loops
#   or use `binwalk -e` which splits them, or `unmkinitramfs` (Ubuntu).
```

## romfs

Tiny read-only FS (`-rom1fs-` magic), common on RTOS/eCos devices.
`7z x blob.romfs`, binwalk's romfs extractor, or `romfsck -x`.

## YAFFS/YAFFS2

NAND FS with OOB/spare data interleaved. `unyaffs blob.yaffs` for simple
images; for raw NAND dumps you must know page+OOB layout
(`yaffshiv` — github.com/devttys0/yaffshiv — brute-forces the layout).

## Raw compression streams

| Stream | Detect | Unpack |
|--------|--------|--------|
| gzip   | `1f 8b` | `gunzip < blob > out` (ignores trailing garbage with exit 2 — output is still valid) |
| LZMA   | `5d 00 00` (lc/lp/pb byte + dict) | `lzma -dc blob > out` / `7z x`; vendor streams with bad size fields: `unlzma --single-stream`, or sasquatch-style brute force |
| XZ     | `fd 37 7a 58 5a` | `xz -dc blob > out` |
| LZ4    | `04 22 4d 18` (frame) / legacy `02 21 4c 18` | `lz4 -d blob out`; kernel "lz4 legacy": `lz4 -d -l` |
| zstd   | `28 b5 2f fd` | `zstd -d blob -o out` |
| bzip2  | `42 5a 68` | `bzip2 -dc blob > out` |
| LZO    | kernel lzop stream | `lzop -d`; raw lzo1x needs a small python-lzo script |

Trailing-garbage trick: carves from `--dd` run to end-of-file; decompressors
that stream (gzip, xz, zstd) stop at end-of-stream and the data is fine —
don't be scared off by the nonzero exit code.

## Whole-image helpers

- `unblob` — modern multi-format extractor, good second opinion when binwalk
  misses: `unblob -e out/ firmware.bin`.
- `7z x firmware.bin` — surprisingly effective on uImage/zip/vendor containers.
- `dumpimage -l firmware.bin` (u-boot-tools) — parse uImage/FIT headers,
  `dumpimage -T flat_dt -p 0 -o kernel fit.itb` to pull FIT components.
- `vmlinux-to-elf` — rebuild an analyzable ELF from a raw extracted kernel.
