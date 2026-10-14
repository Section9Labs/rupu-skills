# binwalk reference — v2 (Python) and v3 (Rust)

Determine the version: `binwalk --help` — v3 prints `Binwalk v3.x.x`, v2
prints `Binwalk v2.x.x` and a much longer option list.

## v2 (Python) flags

### Signature scanning
| Flag | Meaning |
|------|---------|
| `-B, --signature` | Scan for common file signatures (default when no scan type given) |
| `-R, --raw=<str>` | Scan for a custom raw byte sequence (`\x` escapes allowed) |
| `-A, --opcodes` | Scan for executable opcode signatures → guess CPU architecture |
| `-m, --magic=<file>` | Use a custom magic file |
| `-b, --dumb` | Disable smart signature keywords (more hits, more false positives) |
| `-I, --invalid` | Show results marked invalid |
| `-x, --exclude=<regex>` | Exclude signatures matching regex |
| `-y, --include=<regex>` | Only scan signatures matching regex |

### Extraction
| Flag | Meaning |
|------|---------|
| `-e, --extract` | Automatically extract known file types via configured extractors |
| `-D, --dd=<type:ext[:cmd]>` | Carve signatures whose description matches `type` regex into `.ext`, optionally run `cmd` on each (`%e` = carved path). `--dd='.*'` carves everything |
| `-M, --matryoshka` | Recursively scan extracted files (combine with `-e`) |
| `-d, --depth=<n>` | Matryoshka recursion limit (default 8) |
| `-C, --directory=<dir>` | Extract into `<dir>` instead of cwd |
| `-j, --size=<n>` | Limit size of each carved file |
| `-n, --count=<n>` | Limit number of carved files |
| `-0, --squash` | *(some builds)* run extractor as a specific user |
| `--run-as=root` | Required to extract when running as root |
| `-r, --rm` | Delete carved files after extraction (avoid — keep evidence) |
| `-z, --carve` | Carve data from files, do not run extractors |
| `--subdirs` | Extract into per-offset subdirectories |

Extractor configuration lives in `extract.conf` / plugin dirs
(`$HOME/.config/binwalk/`); each rule maps a signature description regex to a
carve extension and an external command (`unsquashfs`, `jefferson`,
`sasquatch`, `cpio`, `7z`, `ubireader_extract_files`, `lzop`, `srec2bin`…).
Install the extractor binaries or `-e` silently leaves raw carves behind.

### Entropy / analysis
| Flag | Meaning |
|------|---------|
| `-E, --entropy` | Entropy plot (matplotlib) + rising/falling edge offsets on stdout |
| `-F, --fast` | Faster but less accurate entropy |
| `-J, --save` | Save plot as PNG instead of displaying |
| `-Q, --nlegend` | Omit plot legend |
| `-N, --nplot` | No plot, just the edge table — ideal headless |
| `-H, --high=<f>` / `-L, --low=<f>` | Rising/falling edge trigger thresholds (defaults ~0.95/0.85) |
| `-W, --hexdump` | Hexdump/diff files (`binwalk -W a.bin b.bin`), with `-G/-i/-U/-u` controls |
| `-Y, --disasm` | Capstone-based disassembly scan → identifies arch + endianness of raw code |
| `-T, --minsn=<n>` | Minimum consecutive valid instructions for `-Y` |
| `-k, --continue` | `-Y`: don't stop at first match |

### General
| Flag | Meaning |
|------|---------|
| `-l, --length=<n>` | Bytes to scan |
| `-o, --offset=<n>` | Start offset |
| `-O, --base=<n>` | Add base to displayed offsets |
| `-K, --block=<n>` | Signature scan block/alignment size |
| `-g, --swap=<n>` | Reverse every n bytes before scan (byte-swapped flash dumps) |
| `-f, --log=<file>` | Log results to file |
| `-c, --csv` | CSV log format |
| `-t, --term` | Fit output to terminal |
| `-q, --quiet` | Suppress stdout |
| `-v, --verbose` | Verbose (shows extractor commands run — use when extraction fails) |
| `-a, --finclude` / `-p, --fexclude` | Only scan / skip files whose names match regex |
| `-s, --status=<port>` | Status server on port |

Reading signature output: three columns — `DECIMAL`, `HEXADECIMAL`, `DESCRIPTION`.
Offsets are from file start. Descriptions embed metadata: image sizes, CRCs,
compression types, timestamps, load/entry addresses (uImage), uncompressed
sizes (LZMA/SquashFS). Sanity-check sizes against the file size: a "16 EB
uncompressed" LZMA hit is a false positive.

## v3 (Rust rewrite) flags

```
binwalk [OPTIONS] <file>
  -e, --extract            extract known file types (default extractors)
  -M, --matryoshka         recursive extraction
  -c, --carve              carve all signature matches to disk, no extractors
  -E, --entropy            entropy analysis; plots in-terminal, saves PNG
  -d, --directory <DIR>    output directory (default ./extractions)
  -l, --log <FILE>         write JSON results log
  -q, --quiet              suppress stdout
  -a, --list               list supported signatures / extractors
  -x, --exclude <sig>      exclude signature (short name from --list)
  -y, --include <sig>      only these signatures
  -s, --search-all         full search: don't stop at first match per block
  -t, --threads <N>        worker threads
  -o, --offset / -L, --length   scan window
```

Notes:
- v3 has **no `-A` opcode scan and no `-Y` capstone scan**. For raw-blob arch
  guessing keep a v2 install around (`pip install binwalk==2.3.*` in a venv),
  or use `cpu_rec`, or carve code and brute-force with `objdump`/capstone.
- v3 extractors are built-in Rust where possible (SquashFS, gzip, etc.) and
  shell out otherwise; it is much faster and does not need the Python
  dependency zoo.
- v3 `-l results.json` gives machine-readable output — prefer it when
  scripting; v2 equivalent is `-f log.txt -c` (CSV).
- v3 entropy renders in the terminal and writes `<file>.png`; no matplotlib.
- Signature short names for `-x/-y` differ from v2's description regexes —
  check `binwalk --list`.

## Practical recipes

```sh
# Headless entropy edge table only (v2)
binwalk -E -N firmware.bin
# Extract just the squashfs, skip a hanging LZMA false positive (v2)
binwalk -e -y 'squashfs' firmware.bin
# Carve everything raw when extractors fail
binwalk --dd='.*' firmware.bin           # v2
binwalk --carve firmware.bin             # v3
# Byte-swapped SPI flash dump (16-bit swapped)
binwalk -g 2 -e firmware.bin             # v2
# Arch of a raw bare-metal blob (v2)
binwalk -A firmware.bin | sort | uniq -c | sort -rn | head
binwalk -Y -T 50 firmware.bin
# Diff two firmware versions (find the patched bytes / the decryptor delta)
binwalk -W old.bin new.bin
```

Manual carve at a known offset (entropy step, signature hit):

```sh
dd if=firmware.bin of=payload.bin bs=1 skip=$((0x40000))        # exact
dd if=firmware.bin of=payload.bin bs=4096 skip=64               # fast, aligned
```
