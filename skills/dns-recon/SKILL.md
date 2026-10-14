---
name: dns-recon
description: DNS reconnaissance and subdomain enumeration (udp/tcp 53) for external/perimeter scope — passive discovery (subfinder, amass, CT logs), direct interrogation and zone transfers (dig, host, dnsrecon), brute-force and permutations (puredns, dnsenum, fierce), bulk resolution/validation (massdns, dnsx), reverse PTR sweeps, and ASN pivoting. Produces a validated live-host/IP list that feeds the recon flow (nmap/naabu port scanning). Use at the start of any external engagement to map the target's DNS attack surface.
license: Apache-2.0
compatibility: Linux; requires subfinder, amass, dnsx, massdns, puredns, dnsrecon, dnsenum, fierce, dig/host; Python 3 for parsing
metadata:
  author: Section9Labs
  stage: reconnaissance
  ports: "53/udp, 53/tcp"
---

# DNS Reconnaissance & Subdomain Enumeration

Map a target organization's entire DNS footprint, validate what is live, and hand
the resulting hosts/IPs to the port-scanning stage of the `recon` flow.

Pipeline: **passive → direct interrogation → active brute → resolve → validate → handoff**.
Each stage feeds candidate names into the next; nothing is a target until `dnsx`/`massdns`
confirms it resolves. Full flag detail, resolver hygiene, and wildcard handling live in
`references/workflow.md`.

## 0. Setup

```bash
mkdir -p dnsrecon-example.com && cd dnsrecon-example.com
# Fresh validated resolver list (critical for massdns/puredns accuracy):
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
# Trusted resolvers for the final validation pass:
printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n' > trusted.txt
```

API keys in `~/.config/subfinder/provider-config.yaml` (SecurityTrails, Shodan, Censys,
VirusTotal, Chaos, GitHub…) multiply passive coverage — configure them before running.

## 1. Direct DNS interrogation

Baseline records and name-server identification:

```bash
dig example.com A +short; dig example.com AAAA +short
dig example.com MX +short; dig example.com TXT +short
dig example.com NS +short; dig example.com SOA +noall +answer
dig www.example.com CNAME +short
host -t any example.com                 # quick combined view
dig example.com ANY @ns1.example.com    # ANY against the authoritative NS, not a public resolver
```

Read it: NS records reveal hosting/infra (self-hosted vs managed DNS); MX reveals mail
provider; TXT reveals SPF/DKIM/verification strings that leak SaaS vendors and sometimes
internal hostnames and IP ranges (`include:` and `ip4:` in SPF); CNAMEs reveal CDNs,
cloud services, and takeover candidates.

**Zone transfer (AXFR) — attempt against EVERY authoritative NS**, misconfigurations are
often on one secondary only:

```bash
for ns in $(dig example.com NS +short); do
  echo "== $ns =="; dig axfr example.com @"$ns"
done
dnsrecon -d example.com -t axfr          # same test, automated across all NS
```

A successful AXFR dumps the full zone — every host, every record — and is itself a
reportable finding (information disclosure). Save the output verbatim as evidence.

**Reverse PTR sweep** once you know target netblocks:

```bash
dnsrecon -r 203.0.113.0/24 -n 1.1.1.1
echo 203.0.113.0/24 | dnsx -ptr -resp -silent -o ptr.txt
```

PTR names expose hosts with no forward record and confirm netblock ownership.

## 2. Passive subdomain discovery

No packets to the target — pure OSINT. Run both, they overlap imperfectly:

```bash
subfinder -d example.com -all -silent -o subfinder.txt
amass enum -passive -d example.com -o amass.txt
```

`-all` enables every subfinder source (slower, far more complete). Certificate
Transparency directly, when APIs are rate-limited:

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | python3 -c 'import json,sys; [print(n) for e in json.load(sys.stdin) for n in e["name_value"].split("\n")]' \
  | sort -u > crtsh.txt
```

**Org/ASN pivoting** to find sibling domains and netblocks beyond the seed domain:

```bash
amass intel -org "Example Corp"          # ASNs + CIDRs registered to the org
amass intel -asn 64496                   # domains seen inside an ASN
amass intel -cidr 198.51.100.0/24 -whois # domains hosted in a netblock
```

Feed any new root domains back through this whole pipeline.

## 3. Active brute-force & permutations

```bash
# puredns: fastest, wildcard-aware brute (preferred)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  example.com -r resolvers.txt --resolvers-trusted trusted.txt -w puredns.txt

# dnsrecon brute + std enumeration
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/namelist.txt -c dnsrecon.csv
dnsrecon -d example.com -t std,srv -c dnsrecon-std.csv   # std records + SRV scan

# dnsenum: whois + brute + reverse in one
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o dnsenum.xml

# fierce: locates nearby IP space around found hosts
fierce --domain example.com --subdomain-file /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

# amass active mode: brute + zone walking + cert grabbing on target infra
amass enum -active -brute -d example.com -o amass-active.txt
```

**Permutations** (altdns/gotator-style methodology): take resolved names and generate
mutations — `dev-`, `-stg`, `api2`, number increments, env prefixes/suffixes, word swaps
(`dev.api.example.com` → `prod.api.example.com`) — then push the mutation list back
through `puredns resolve`/`massdns`. Iterate until the resolved set stops growing.

```bash
gotator -sub resolved_hosts.txt -perm permutation-words.txt -depth 1 -mindup -silent > perms.txt
puredns resolve perms.txt -r resolvers.txt --resolvers-trusted trusted.txt -w perms-resolved.txt
```

Wildcard DNS (`*.example.com` answers everything) will flood naive brute-forcers with
false positives — `puredns` and `dnsx` handle this; see `references/workflow.md` for
manual detection (`dig <random>.example.com`) and filtering.

## 4. Bulk resolution & validation

Merge every candidate source, dedupe, resolve at speed, validate with trusted resolvers:

```bash
cat subfinder.txt amass.txt crtsh.txt puredns.txt perms-resolved.txt \
  | tr 'A-Z' 'a-z' | sed 's/\.$//' | sort -u > all-names.txt

# High-speed first pass (public resolver list; expect some poisoned answers):
massdns -r resolvers.txt -t A -o S -w massdns.txt all-names.txt

# Validation pass: trusted resolvers, wildcard stripping, full response capture:
dnsx -l all-names.txt -a -aaaa -cname -resp -silent -r trusted.txt -wd example.com -o resolved.txt
```

Read `resolved.txt`: `host [A] [192.0.2.10]` lines give live host→IP pairs; `[CNAME]`
lines pointing at external services (S3, Azure, Heroku, GitHub Pages…) that do NOT
resolve further are **subdomain-takeover candidates** — verify the dangling target and
report. Map the resolved IPs to netblocks/ASNs (`whois -h whois.cymru.com " -v <ip>"`)
and feed newly discovered CIDRs back to the PTR sweep (step 1) and `amass intel` (step 2).

**Vhost note:** DNS enumeration finds *names that resolve*. Virtual hosts served on an
already-found IP without a DNS record are a web-layer concern — brute them with the
`web-testing` skill (Host-header fuzzing) against the IPs you hand off; do not duplicate
that here.

## 5. Parse, consolidate, hand off

```bash
python3 scripts/parse_dns.py \
  --out-dir out \
  resolved.txt massdns.txt subfinder.txt amass.txt dnsrecon.csv ptr.txt
```

Auto-detects subfinder/amass/massdns/dnsx/dnsrecon/plain formats and emits into `out/`:

- `resolved_hosts.txt` — `hostname<TAB>ip[,ip…]` for every validated pair
- `scan-targets.txt` — unique live IPs, one per line
- `work-units.json` — clean JSON **array** (first byte `[`) of
  `{id,title,targets,hints}` port-scan work units, grouped by /24 netblock

**Handoff into the `recon` flow:** `scan-targets.txt` is the input target list for the
`naabu` skill (fast port sweep) and the `nmap` skill (service/version enumeration);
`resolved_hosts.txt` supplies hostnames for TLS SNI, vhost brute, and web screenshotting.
`work-units.json` is rupu-ingestible — see `references/rupu.md` for driving a
`for_each:`/`dispatch` fan-out and for recording assets and findings. That reference
imports the shared reporting-pack skills `work-units`, `coverage-assets`, and
`finding-report`; use those, do not re-invent the formats.

Findings to report from this stage: **zone transfer allowed** (AXFR dump as evidence),
**subdomain takeover candidates** (dangling CNAMEs), **wildcard misconfiguration**, and
**information disclosure via TXT/SPF/PTR** (internal names, ranges, vendor list).
