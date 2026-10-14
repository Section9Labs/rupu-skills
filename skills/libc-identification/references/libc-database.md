# libc-database full workflow

Repo: https://github.com/niklasb/libc-database (web frontend by blukat29 at
https://libc.blukat.me, API at https://libc.rip).

## Layout

```
libc-database/
  get            # downloader
  find           # search by symbol + low 12 bits
  dump           # print offsets for a build id
  add            # index a local libc file
  identify       # match a local libc file against the db by hash
  download       # fetch the full package (libc + matching ld) for an id
  db/            # <id>.so, <id>.symbols, <id>.info per indexed build
```

## get — populate the database

```bash
./get                      # default set (ubuntu)
./get ubuntu debian        # specific distros
./get all                  # everything: ubuntu debian arch centos kali parrot launchpad
./get ubuntu &             # resumable; re-run to pick up new releases
```

Each build becomes `db/<id>.so` + `db/<id>.symbols` (nm output of dynamic
symbols plus pseudo-symbols like `str_bin_sh` and `__libc_start_main_ret`).
`./get all` is tens of GB; for most engagements `ubuntu debian` suffices.

## find — match a leak

Only the low 12 bits matter (ASLR is page-granular):

```bash
./find puts 5a0
./find puts 0x7f3c6a4b85a0        # full addresses accepted; low bits extracted
./find puts 5a0 printf 710        # AND of both constraints — use whenever you have 2 leaks
./find __libc_start_main_ret b97  # stack-leak pseudo-symbol
```

Output format: one candidate per line, `<source-name> (id <build-id>)`.
Grep-friendly: the id inside `(id ...)` is what `dump`/`download` take.

Zero results: the build isn't indexed. Either `./get` more distros, hit the
web API (its corpus is larger and includes launchpad historical builds), or
reconsider whether the leak is really libc (see SKILL.md pitfalls).

## dump — resolve offsets

```bash
./dump libc6_2.31-0ubuntu9.9_amd64
# default set: __libc_start_main_ret, system, dup2, read, write, str_bin_sh
./dump libc6_2.31-0ubuntu9.9_amd64 puts gets system str_bin_sh __free_hook \
    __malloc_hook _IO_list_all environ _IO_2_1_stdout_
```

Lines are `offset_<symbol> = 0x<hex>`. `environ` is worth grabbing: libc's
copy of the environment pointer → a stack leak → return-address overwrite
target for `heap-exploitation` arbitrary writes.

## add / identify / download

```bash
./add /loot/example.com/libc.so.6     # index a libc you exfiltrated
./identify ./libc.so.6                # is this exact file already indexed? (by hash)
./download libc6_2.31-0ubuntu9.9_amd64
# → fetches the full .deb contents: libc-2.31.so AND the matching ld-2.31.so
```

`./download` is the step people forget: it gives you the matching **loader**
needed to run the target locally (see running-with-a-given-libc.md) and the
exact `.so` to feed to `one_gadget`:

```bash
one_gadget db/libc6_2.31-0ubuntu9.9_amd64.so
# 0xe3afe execve("/bin/sh", r15, r12)   constraints: [r15] == NULL || r15 == NULL ...
```

## Web API (libc.rip)

```bash
# find by symbols
curl -s https://libc.rip/api/find -H 'Content-Type: application/json' \
  -d '{"symbols": {"puts": "5a0", "printf": "710"}}' | python3 -m json.tool

# dump specific symbols for a known id
curl -s https://libc.rip/api/libc/libc6_2.31-0ubuntu9.9_amd64 \
  -H 'Content-Type: application/json' | python3 -m json.tool
```

`api/find` response objects carry: `id`, `buildid`, `md5/sha1/sha256`,
`symbols` (the ones you queried plus the common set), `download_url`,
`symbols_url`, `libs_url`. Download the `.so` from `download_url` and treat
it exactly like a local `db/<id>.so`.

Picking between candidates when two leaks still leave several: compare
`buildid` against anything you can read remotely (`/proc/self/maps` paths,
banner versions, `ldd --version` output from an RCE foothold), or just dump
all candidates — if `offset_system` and `offset_str_bin_sh` agree across
them, the ambiguity doesn't matter for a ret2libc.
