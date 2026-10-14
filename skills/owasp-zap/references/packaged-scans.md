# ZAP packaged scan scripts (Docker)

Image: `ghcr.io/zaproxy/zaproxy:stable` (also `:weekly`, `:bare` for minimal
CI). Always mount the working directory so reports and configs survive:

```sh
docker run --rm -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable <script> ...
```

Report paths given to the scripts are relative to `/zap/wrk/`.

## The three scripts

| Script | What it does | Attack traffic? |
|---|---|---|
| `zap-baseline.py` | spider (1 min default) + passive scan only | No — safe anywhere |
| `zap-full-scan.py` | spider (unlimited default) + **active scan** | Yes |
| `zap-api-scan.py` | import API defn + custom API active-scan policy + optional active rules tuned for APIs | Yes |

## Shared flags (all three)

| Flag | Meaning |
|---|---|
| `-t <target>` | target URL (for api-scan: the definition file/URL) |
| `-r f.html` / `-w f.md` / `-x f.xml` / `-J f.json` | write report(s) |
| `-c conf` / `-u url` | per-rule config file/URL: lines `ruleid<TAB>IGNORE|INFO|WARN|FAIL<TAB>comment`; generate a template with `-g gen.conf` |
| `-I` | do NOT fail the exit code on WARN (report-only CI) |
| `-l PASS\|IGNORE\|INFO\|WARN\|FAIL` | minimum level to show in output |
| `-j` | also run the AJAX spider (baseline/full) |
| `-m N` | spider minutes (baseline) |
| `-T N` | max total scan minutes (full/api) |
| `-D N` | wait N seconds for passive scan to finish |
| `-n ctx.context` | import a saved context file (export from GUI); `-U user` scan as that context user |
| `-z "-config k=v -config k2=v2"` | pass raw ZAP `-config` options through |
| `--hook hooks.py` | Python hook file to customize the scan lifecycle |
| `-a` | include alpha passive rules (baseline) / alpha active (api-scan) |
| `-d` | debug output |
| `-P port` / `-p port` | listen port / existing-ZAP port |
| `-s` | no safe-mode fallback on target errors |

Exit codes: `0` pass, `1` at least one FAIL alert, `2` at least one WARN (suppressed by `-I`), `3` script/target error.

## Worked invocations

Baseline (passive, CI-friendly):

```sh
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://app.example.com \
  -J report.json -r report.html -w report.md \
  -j -m 5 -I
```

Full active scan with rule overrides:

```sh
cat > rules.conf <<'EOF'
10096	IGNORE	(Timestamp disclosure - noisy)
40018	FAIL	(SQL injection must fail the build)
EOF
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://app.example.com \
  -J report.json -r report.html -c rules.conf -T 120 -j
```

API scan from an OpenAPI definition, with a bearer token injected into every
request via raw configs (the api-scan images honor the `replacer` configs):

```sh
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t /zap/wrk/openapi.json -f openapi \
  -J report.json -r report.html -I \
  -z "-config replacer.full_list(0).description=auth \
      -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).replacement=Bearer\ eyJ..."
```

`-f` accepts `openapi | soap | graphql`; `-t` may be a URL
(`-t https://api.example.com/openapi.json`) or a mounted file path. For
GraphQL point `-t` at the schema (or introspection endpoint URL).

Authenticated baseline using an exported context:

```sh
docker run --rm -v $(pwd):/zap/wrk/:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://app.example.com -n app.context -U alice -J report.json -I
```

Hooks (`--hook /zap/wrk/hooks.py`) let you customize without forking the
script — define functions like `zap_started(zap, target)` (gets the live
`zapv2` client: add replacer rules, auth, globalexcludeurl here) or
`zap_pre_shutdown(zap)` (pull extra data before exit).

## Handoff

`-J report.json` is the traditional-json report — same schema the Automation
Framework `report` job writes. Parse it:

```sh
python3 scripts/parse_zap_report.py report.json \
  --out alerts.json --work-units wu.json --findings findings.json
```

Then per `references/rupu.md`: `assets.mark` the site (`mapped`) and every
reported route (`crawled`/`tested`), hand `wu.json` to the `work-units` skill
for fan-out, and file confirmed alerts via the `finding-report` skill.
