# arjun — full reference

Install: `pipx install arjun` (or `pip install arjun`). Verify with `arjun -h`.

## How arjun decides a parameter is real (differential response analysis)

1. **Baseline learning.** Arjun requests the target several times with no
   extra params and with a few random junk params. It records status code,
   content length, plain-text content (HTML stripped), and whether injected
   values reflect. Natural jitter (timestamps, CSRF tokens, ads) is factored
   into the comparison so it is tolerated later.
2. **Chunked probing.** The wordlist is split into chunks (default 500 names
   per request). Each chunk is sent at once — GET query string, POST body,
   JSON object, or XML, per `-m` — with randomized values.
3. **Anomaly detection.** A chunk is "interesting" if, versus baseline, any
   of these change: HTTP status, body length beyond learned jitter, presence
   of a reflected value, appearance/disappearance of text, redirect location.
4. **Binary search.** An interesting chunk is split in half repeatedly until
   the single responsible parameter is isolated. Each confirmed param is
   re-verified individually before being reported.

Consequence: every reported param has observable server-side effect. The
"based on: X" reason in the console output tells you *what* effect:

- `based on: body length` / `text` — behavior change; param is processed.
- `based on: reflection` — value echoed into the response: XSS/injection lead.
- `based on: status code` — often auth/debug/feature toggles, error switches.
- `based on: redirection` — open-redirect candidates.

## Flags

| flag | meaning |
|---|---|
| `-u URL` | single target |
| `-i FILE` | import targets: newline URL list, Burp request/export XML, or a raw HTTP request file |
| `-m GET\|POST\|JSON\|XML` | where params are injected (query string / form body / JSON object / XML). One method per run |
| `-w PATH` or `-w small\|medium\|large` | wordlist; default is arjun's bundled large list (~25k names) |
| `-t N` | threads (default 5; 10–20 is usually safe) |
| `-d SECONDS` | delay between requests |
| `-c N` | chunk size (default 500). Lower to 100–250 if baseline chunks return 400/413/414/431 or the WAF trips on long query strings; raise to 1000+ on tolerant APIs for speed |
| `--headers "H1: v\nH2: v"` | custom headers — cookies, Authorization, Content-Type overrides. Also accepts an interactive multiline prompt if given with no value |
| `--include 'a=b&c=d'` or `--include '{"a":"b"}'` | static data appended to **every** request (required tokens, API keys, fixed fields) so the baseline stays valid |
| `--stable` | slow/careful mode: more baseline requests, stricter anomaly thresholds. Use on dynamic pages (rotating content, LB with mixed backends) or when output is obviously noisy |
| `--passive[=domain]` | no fuzzing — mine param names seen historically for the host from Wayback Machine, CommonCrawl, OTX. Combine with normal runs: merge mined names into your wordlist |
| `--rate-limit N` | requests/second cap when the target drops you |
| `--casing like\|Like\|LIKE\|l-ike\|l_ike` | force output param casing style to match app convention |
| `-q` | quiet (clean logs for automation) |
| `-oJ FILE` | JSON results — **use this for parsing** |
| `-oT FILE` | plain text results |
| `-oB [host:port]` | replay each confirmed param through Burp (default 127.0.0.1:8080) |

There is **no plain `-o`** flag.

## JSON output shape

Current versions write a map keyed by URL:

```json
{
  "https://example.com/api/profile": {
    "params": ["id", "debug", "fields"],
    "method": "GET",
    "headers": {"User-Agent": "..."}
  }
}
```

Older versions wrote `{"https://example.com/api/profile": ["id", "debug"]}`.
`scripts/parse_arjun.py` accepts both.

## Operational notes

- **Run each method separately** and keep separate output files; an endpoint
  frequently accepts different params via GET vs JSON body.
- **Authenticated vs anonymous:** rerun with `--headers "Cookie: ..."`. Params
  only visible when authed (e.g. `role`, `impersonate`) are the best IDOR /
  privilege-escalation leads; params only visible unauthed hint at
  pre-auth debug surface.
- **Unstable target symptoms:** arjun reports dozens of params or warns the
  target is unreliable → rerun with `--stable`, lower `-t`, add `-d 1`.
- **Required-field APIs:** if the endpoint 400s without a mandatory field,
  arjun's baseline is a useless error page. Supply the mandatory data with
  `--include` so the differential works on the real code path.
- **Burp handoff:** `-oB` is the fastest way to get every confirmed param
  into Repeater for manual value testing.
