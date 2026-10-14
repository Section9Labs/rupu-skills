# DNS Recon Pipeline — Full Reference

Stage order: **passive → direct interrogation → active brute → permutations →
resolve → validate → pivot → handoff**. Re-run the resolve/validate stage every
time a new candidate source is added; re-run the pivot stage every time a new
IP range or root domain surfaces.

## 1. Resolver-list hygiene (do this first)

massdns/puredns throughput and *accuracy* depend entirely on the resolver list.
Public resolver lists rot: dead resolvers slow you down, lying/poisoning
resolvers inject fake answers that pollute the result set.

```bash
# Pull a maintained list (refreshed daily):
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# Or validate your own list with dnsvalidator:
dnsvalidator -tL resolvers-raw.txt -threads 100 -o resolvers.txt

# Keep a short TRUSTED list for the final validation pass:
printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n' > trusted.txt
```

Rule: **brute and mass-resolve with the big public list; accept nothing into the
final set until it re-resolves against trusted resolvers** (`puredns`'s
`--resolvers-trusted` and a final `dnsx -r trusted.txt` pass both do this).

## 2. Direct interrogation — dig/host flag reference

```bash
dig example.com A +short                     # terse answer only
dig example.com +noall +answer               # answer section, with TTL/class
dig example.com NS +short                    # authoritative name servers
dig example.com SOA +noall +answer           # serial, primary NS, admin contact
dig example.com MX +short                    # mail exchangers
dig example.com TXT +short                   # SPF/DKIM/verification strings
dig -x 203.0.113.10 +short                   # single PTR lookup
dig example.com A @ns1.example.com           # query a specific server
dig +trace example.com                       # full delegation path from root
dig example.com +tcp                         # force TCP/53 (large answers, filters)
dig example.com ANY @ns1.example.com         # ANY — only useful vs authoritative NS
dig example.com +dnssec +noall +answer       # DNSSEC records (DS/RRSIG presence)
host -a example.com                          # dig ANY equivalent
host -t ns example.com; host -t mx example.com
```

Interpretation checklist:
- **SOA serial** format often encodes change dates (`YYYYMMDDnn`); low serials = stale zones.
- **TXT/SPF** `ip4:`/`include:` entries leak netblocks and third-party senders — every
  `include:` is a SaaS vendor; every `ip4:` CIDR goes into the PTR-sweep queue.
- **CNAME chains** terminating off-domain = CDN/cloud mapping; a CNAME to a name that
  returns NXDOMAIN = takeover candidate.
- **NS on target IP space** (self-hosted DNS) = port 53 tcp/udp is a direct service
  target for the port-scan stage, and AXFR/version probing is more likely to succeed.
- `dig version.bind chaos txt @ns1.example.com` — BIND version disclosure.
- DNSSEC with NSEC (not NSEC3): zone walking enumerates every name —
  `ldns-walk example.com` or `amass enum -active` exploits this automatically.

## 3. Zone transfers (AXFR)

Try **every** authoritative NS — secondaries are misconfigured more often than primaries:

```bash
for ns in $(dig example.com NS +short); do
  echo "===== $ns ====="
  dig axfr example.com @"$ns" | tee "axfr-${ns%.}.txt"
done
dnsrecon -d example.com -t axfr -j axfr.json
host -l example.com ns2.example.com          # host(1) equivalent
```

Success = full RR dump (watch for the SOA at start and end). Failure modes:
`Transfer failed.`, `communications error`, or a REFUSED status. A refused UDP
query but open TCP/53 still warrants the attempt (`dig +tcp axfr ...`). Also try
AXFR on in-addr.arpa zones for the target's netblocks:
`dig axfr 113.0.203.in-addr.arpa @ns1.example.com`.

A successful transfer is a **finding** (information disclosure, typically medium
severity externally) — keep the raw dump as evidence and ingest every name into
the candidate set.

## 4. Reverse PTR sweeps

```bash
dnsrecon -r 203.0.113.0/24 -n 1.1.1.1 -c ptr-203.csv
dnsrecon -r 198.51.100.0/24 --threads 30 -c ptr-198.csv
echo 203.0.113.0/24 | dnsx -ptr -resp -silent -o ptr.txt
# From a file of CIDRs:
dnsx -l cidrs.txt -ptr -resp -silent -o ptr.txt
# Classic one-liner spot check:
for i in $(seq 1 254); do host "203.0.113.$i" | grep -v NXDOMAIN; done
```

PTR names frequently reveal: hosts with no forward DNS, internal naming
conventions (`fw01`, `vpn-gw`, `db-prod`), and whether the block is really the
target's or a shared hoster's. Any new domain seen in PTR data is a pivot:
run it through the whole pipeline.

## 5. Passive discovery — full flags

### subfinder
```bash
subfinder -d example.com -all -silent -o subfinder.txt
subfinder -dL domains.txt -all -silent -o subfinder-all.txt   # multiple roots
subfinder -d example.com -all -recursive -silent              # recurse into found subs
subfinder -ls                                                  # list sources
subfinder -d example.com -sources securitytrails,censys,shodan # cherry-pick sources
```
Keys live in `~/.config/subfinder/provider-config.yaml`. Without keys you get
maybe 30–50% of what a keyed run returns — SecurityTrails, Censys, Shodan,
VirusTotal, Chaos, and GitHub are the highest-yield sources.

### amass
```bash
amass enum -passive -d example.com -o amass.txt
amass enum -passive -df domains.txt -o amass.txt
amass enum -active -brute -d example.com -w wordlist.txt -o amass-active.txt
amass enum -d example.com -config config.yaml                 # keyed datasources
amass db -names -d example.com                                # dump prior-run graph DB
# Org / ASN / netblock pivoting:
amass intel -org "Example Corp"
amass intel -asn 64496 -o asn-domains.txt
amass intel -cidr 198.51.100.0/24 -whois
amass intel -d example.com -whois                             # reverse-whois siblings
```
Note: amass v4 output lines may be relationship triples
(`www.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)`) rather than
bare names — `scripts/parse_dns.py` handles both.

### Certificate Transparency
```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | python3 -c 'import json,sys; [print(n) for e in json.load(sys.stdin) for n in e["name_value"].split("\n")]' \
  | sort -u > crtsh.txt
```
CT shows historical names too — stale entries that no longer resolve are prime
takeover candidates once validated against current DNS. Other CT frontends:
censys.io certificates search, `tlsx -san -cn` against live IPs.

## 6. Active brute-force — full flags

### puredns (preferred: speed + wildcard sanitation built in)
```bash
puredns bruteforce wordlist.txt example.com \
  -r resolvers.txt --resolvers-trusted trusted.txt \
  --rate-limit-trusted 100 -w puredns.txt --write-massdns puredns-massdns.txt
puredns resolve candidates.txt -r resolvers.txt --resolvers-trusted trusted.txt -w resolved.txt
```
puredns workflow internally: mass-resolve on public resolvers → detect wildcard
roots by resolving random labels → strip wildcard-matched answers → re-validate
survivors on trusted resolvers. `--write-massdns` keeps the raw record data for parsing.

### dnsrecon
```bash
dnsrecon -d example.com -t brt -D wordlist.txt -c brt.csv -j brt.json
dnsrecon -d example.com -t std -c std.csv        # SOA/NS/MX/A/AAAA/TXT/SRV baseline
dnsrecon -d example.com -t srv                   # SRV scan (_ldap._tcp, _sip._tls, …)
dnsrecon -d example.com -t zonewalk              # NSEC zone walking
dnsrecon -d example.com -t crt                   # crt.sh scrape
dnsrecon -d example.com -t snoop -D hostnames.txt -n ns1.example.com  # cache snooping
```

### dnsenum
```bash
dnsenum --enum example.com -f wordlist.txt --threads 20 -o dnsenum.xml
# --enum = --dnsserver auto + whois + reverse lookups on found class-C blocks
dnsenum example.com --noreverse -f wordlist.txt   # skip the reverse pass
```
dnsenum's reverse-lookup of surrounding /24s around found IPs often reveals
sibling infrastructure — the same idea fierce automates.

### fierce
```bash
fierce --domain example.com
fierce --domain example.com --subdomain-file hostlist.txt
fierce --domain example.com --wide            # scan whole /24 around each hit
fierce --domain example.com --traverse 20     # ±20 IPs around each hit
fierce --domain example.com --dns-servers ns1.example.com   # use target's own NS
```
fierce's value is the **nearby-IP traversal**: finding one host at 203.0.113.37
and PTR-scanning its neighbors maps the netblock fast.

## 7. Wildcard detection & handling

Detect manually before any brute run:

```bash
dig "$(head -c16 /dev/urandom | md5sum | cut -c1-12).example.com" +short
# Non-empty answer => wildcard. Note the IP(s)/CNAME it returns.
```

Handling strategies:
- **puredns**: automatic — resolves random labels per level, strips matching answers.
- **dnsx**: `-wd example.com` enables wildcard filtering for the domain.
- **Manual**: resolve 3–5 random labels, collect the wildcard answer set
  (IPs/CNAMEs), then drop any brute result whose entire answer set ⊆ wildcard set.
  Keep results that return *different* records — those are real hosts shadowing
  the wildcard.
- Multi-level wildcards exist (`*.dev.example.com` with its own answer): test a
  random label under every discovered sub-zone, not just the apex.
- A wildcard pointing at a decommissioned or third-party service is itself a
  **wildcard misconfiguration finding** (phishing/takeover surface).

## 8. Permutation generation

Take only *resolved* names as seeds (permuting garbage multiplies garbage):

```bash
gotator -sub resolved_hosts.txt -perm permutation-words.txt -depth 1 -numbers 3 -mindup -silent > perms.txt
# or altdns:
altdns -i resolved_hosts.txt -o perms.txt -w permutation-words.txt
# or dnsgen:
dnsgen resolved_hosts.txt > perms.txt
puredns resolve perms.txt -r resolvers.txt --resolvers-trusted trusted.txt -w perms-resolved.txt
```

Permutation word seeds: `dev test stg stage staging qa uat prod int internal
corp admin api app web mail vpn old new 01 02 2 3 v2`. Also harvest the
target's own naming tokens from already-resolved names (split on `.-`), they
outperform generic lists. Iterate: resolved output → new seeds → repeat until
the delta is empty.

## 9. Mass resolution & validation — full flags

### massdns
```bash
massdns -r resolvers.txt -t A    -o S -w massdns-a.txt    all-names.txt
massdns -r resolvers.txt -t AAAA -o S -w massdns-aaaa.txt all-names.txt
massdns -r resolvers.txt -t CNAME -o S -w massdns-cname.txt all-names.txt
massdns -r resolvers.txt -t A -o J -w massdns.jsonl all-names.txt   # ndjson, full detail
# -s <n> controls concurrency (default 10000); -o S = simple "name. TYPE value"
```
massdns output (`-o S`): `www.example.com. A 192.0.2.10` — note the trailing
dot and that CNAME lines show the alias target, not an IP. Treat massdns
results as *candidates*: public resolvers lie.

### dnsx (validation layer)
```bash
dnsx -l all-names.txt -a -aaaa -cname -resp -silent -r trusted.txt -wd example.com -o resolved.txt
dnsx -l all-names.txt -recon -resp -silent          # all record types at once
dnsx -l all-names.txt -cname -resp-only -silent     # just CNAME targets (takeover triage)
dnsx -l ips.txt -ptr -resp -silent                  # PTR mode
dnsx -l all-names.txt -a -resp -json -o resolved.jsonl   # JSON lines for tooling
echo 203.0.113.0/24 | dnsx -ptr -resp -silent       # CIDR expansion built in
```
dnsx `-resp` output format: `www.example.com [A] [192.0.2.10]`. `-wd` strips
wildcard noise; `-rl` sets rate if a resolver throttles you (raise it, default
is unlimited with `-t` threads).

## 10. Reading the resolved set & pivoting

For every validated host→IP pair:

1. **Netblock grouping** — group IPs by /24 (the parser does this). Blocks with
   many target hosts are likely target-owned; single-host blocks are likely
   cloud/CDN.
2. **ASN lookup** — `whois -h whois.cymru.com " -v 203.0.113.10"` or
   `asnmap -i 203.0.113.10`. Target-registered ASNs expand scope: run `amass
   intel -asn <n>`, PTR-sweep the announced CIDRs, add the CIDRs to the
   port-scan queue.
3. **CDN/WAF detection** — IPs in Cloudflare/Akamai/Fastly ranges mean the DNS
   name is fronted; the *origin* may hide in historical DNS (SecurityTrails),
   SPF records, or MX hosts. Don't waste port-scan depth on CDN edges.
4. **Takeover triage** — for every CNAME whose target NXDOMAINs or answers with
   a provider "unclaimed" page (S3 `NoSuchBucket`, GitHub 404, Heroku
   `no such app`, Azure `404 Web Site not found`): fingerprint against the
   can-i-take-over-xyz matrix and report as a finding with the dig output and
   HTTP response as evidence.
5. **Internal leakage** — RFC1918 answers in public DNS, `internal.`/`corp.`
   names, split-horizon artifacts: report as information disclosure, keep the
   names for any later internal phase.

## 11. Handoff contract

Run `python3 scripts/parse_dns.py --out-dir out <all output files>`. Outputs:

| file | content | consumer |
|---|---|---|
| `out/resolved_hosts.txt` | `host<TAB>ip,ip…` | web skills (SNI/vhost), evidence |
| `out/scan-targets.txt` | unique live IPs | `naabu` skill (fast sweep), `nmap` skill (deep enum) |
| `out/work-units.json` | JSON array of port-scan units per netblock | rupu `for_each:`/`dispatch` — see `references/rupu.md` |

Vhost brute against those IPs (Host-header fuzzing for names with no DNS
record) belongs to the `web-testing` skill — hand it `resolved_hosts.txt` and
`scan-targets.txt`, do not duplicate it here.
