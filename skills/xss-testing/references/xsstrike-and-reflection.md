# XSStrike, kxss, Gxss — reflection discovery and context analysis

## kxss (Emoe fork)

Stdin-driven reflected-parameter finder. For every URL with query parameters it injects a
probe per parameter and reports which special characters come back **unencoded** — the
single most useful pre-scan signal, because surviving chars determine the possible break-out.

```sh
gau example.com | kxss
waybackurls example.com | kxss
katana -u https://example.com -d 3 | grep '=' | kxss
```

Output (one line per reflecting param):

```
URL: https://example.com/search?q=kxsstest Param: q Unfiltered: [" ' < >]
URL: https://example.com/item?id=kxsstest Param: id Unfiltered: ["]
```

Interpretation:
- `< >` unfiltered → full tag injection likely: go straight to `<img src=x onerror=...>`.
- `"` only → quoted-attribute break-out (`" onfocus=alert(1) autofocus x="`).
- `'` only → single-quoted attribute or JS-string break-out (`';alert(1);//`).
- Reflects but nothing unfiltered → server encodes; still check DOM paths (the param may
  flow into a sink client-side) and double-encoding/charset tricks before discarding.

Parsing: lines are `URL: <url> Param: <name> Unfiltered: [<chars>]` — regex
`^URL: (\S+) Param: (\S+) Unfiltered: \[(.*)\]`. Feed each (url,param) pair to dalfox:

```sh
cat urls.txt | kxss | awk '{print $2}' | sort -u | dalfox scan -f jsonl -o dalfox.jsonl -S
```

## Gxss (KathanP19) — deprecated but still around

Same niche, less detail: tells you *that* a param reflects, not which chars survive.

```sh
cat urls.txt | Gxss -c 50 -p Rand0mProbe -o reflected.txt
```

- `-c` concurrency, `-p` probe string (pick something unique, default `aprefix`), `-o` output
  file, `-v` include non-reflecting too.
- Output: the URL with the reflecting param's value replaced by the probe.

Upstream marks Gxss deprecated in favor of dalfox's own discovery:
`dalfox file urls.txt --skip-xss-scanning` (jsonl output, pipeline-friendly). Use kxss when
you want the surviving-chars signal, dalfox discovery when you want structured output.

## XSStrike (s0md3v)

`python3 xsstrike.py` — intelligent context analyzer, fuzzing engine, payload generator with
efficiency scoring, WAF detection, and a DOM source/sink scanner. **No machine-readable
output**: it is the *understanding* tool. When XSStrike finds a vector, confirm it manually
and either report via the `finding-report` skill or re-run the exact URL/param through
dalfox to get JSON evidence for the pipeline.

### Flags

| Flag | Meaning |
|---|---|
| `-u URL` | target (GET params in URL) |
| `--data "a=1&b=2"` | POST body; add `--json` if the body is JSON, `--path` to fuzz path components |
| `--crawl` | crawl the target first and test everything found |
| `-l N` | crawl depth (with `--crawl`, default 2) |
| `--fuzzer` | filter/WAF probing mode — sends char/keyword probes, reports passed/filtered/blocked (slow, noisy) |
| `--blind` | inject the blind payload from `core/config.py` into every form while crawling (**only works with `--crawl`**; set your interactsh/XSS Hunter URL in config first) |
| `-f payloads.txt` / `-f default` | bruteforce with your payload list |
| `--skip` | don't prompt to continue POC generation (unattended runs) |
| `--skip-dom` | skip DOM scanning |
| `--headers` | prompt for / supply custom headers (cookies, auth) |
| `-t N` | threads, `-d N` delay seconds, `--timeout N` | 
| `--seeds seeds.txt` | extra URLs to crawl from |
| `--console-log-level / --file-log-level --log-file xs.log` | logging |

### Reading the output

- `Reflections found: N` then per-reflection `Context: HTML / attribute / script / comment`
  — this is the context map; it decides the break-out family.
- `Occurences analyzed` + generated payloads each scored:
  - **Efficiency** 100 = payload reflected exactly (unfiltered); 90s = partially mangled
    but likely workable; low = filtered.
  - **Confidence** = likelihood the payload executes in that context.
- `WAF detected: <name>` → switch to its WAF-evasion payload branch; mirror with dalfox
  `--waf-evasion` later.
- DOM scan: prints `Potentially vulnerable objects found` with highlighted lines — sources
  (`location.*`, `document.referrer`, `window.name`) and sinks (`innerHTML`,
  `document.write`, `eval`...). These are leads: open devtools, set breakpoints on the sink,
  and trace whether the source reaches it (see `contexts-and-payloads.md`).
- `--fuzzer` prints each probe as `[passed]` / `[filtered]` / `[blocked]` — a character-level
  filter map you can use to hand-craft a payload or build `--custom-payload` for dalfox.

### Typical runs

```sh
python3 xsstrike.py -u "https://example.com/search?q=query" --skip
python3 xsstrike.py -u "https://example.com/login" --data "user=q&pass=x" --skip
python3 xsstrike.py -u "https://example.com/" --crawl -l 3 -t 10
python3 xsstrike.py -u "https://example.com/" --crawl --blind      # blind seeding
python3 xsstrike.py -u "https://example.com/s?q=q" --fuzzer -d 1   # filter map
```

### Handoff

For every XSStrike-identified vector: (1) manually confirm execution in a browser,
(2) capture the request/response via a mitmproxy/Burp proxy (`--proxy` is not an XSStrike
flag — set `HTTP_PROXY`/`HTTPS_PROXY` env or re-issue with curl through the proxy),
(3) report with `findings.report` (shape in `rupu.md`) or feed the URL+param to
`dalfox scan ... -f json` so `scripts/parse_dalfox.py` produces the finding payload.
Mark the route `web:route` depth `tested` (or `exploited` once confirmed).
