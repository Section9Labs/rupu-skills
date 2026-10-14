# Transforms, fingerprinting and psk-crack — reference

## IKEv1 transform attribute values

A transform for `--trans=enc,hash,auth,group`:

### Encryption (enc)
| Value | Algorithm |
|---|---|
| 1 | DES-CBC (weak) |
| 2 | IDEA |
| 3 | Blowfish |
| 4 | RC5 |
| 5 | 3DES-CBC |
| 6 | CAST |
| 7/128 | AES-128 (keylen attribute appended with `/`) |
| 7/192 | AES-192 |
| 7/256 | AES-256 |
| 8 | Camellia |

### Hash (hash)
| Value | Algorithm |
|---|---|
| 1 | MD5 (weak) |
| 2 | SHA1 |
| 4 | SHA2-256 |
| 5 | SHA2-384 |
| 6 | SHA2-512 |

### Authentication (auth)
| Value | Method | Note |
|---|---|---|
| 1 | Pre-Shared Key | PSK attack surface |
| 3 | RSA signatures | certificate-based |
| 4 | RSA encryption | rare |
| 64221 | Hybrid mode (Checkpoint) | |
| 65001 | XAUTH init PSK | PSK + user/pass; group PSK still crackable |
| 65003 | XAUTH init RSA | |
| 65005 | XAUTH init RSA-rev | |

### DH group (group)
| Value | Group | Note |
|---|---|---|
| 1 | modp768 | broken |
| 2 | modp1024 | weak (Logjam-class) |
| 5 | modp1536 | |
| 14 | modp2048 | |
| 19/20/21 | ECP 256/384/521 | |

## Transform brute-force methodology

1. Start with the default 8-transform proposal (`ike-scan -M <ip>`).
2. On NO-PROPOSAL-CHOSEN or silence, iterate the common space — 5 enc × 2
   hash × 4 auth × 4 group = 160 probes, seconds of work:

```bash
for enc in 1 5 7/128 7/192 7/256; do
 for hash in 1 2; do
  for auth in 1 3 64221 65001; do
   for grp in 1 2 5 14; do
    sudo ike-scan -M --trans="$enc,$hash,$auth,$grp" 203.0.113.50 2>/dev/null \
      | grep -q "Handshake returned" && echo "MAIN:  $enc,$hash,$auth,$grp"
    sudo ike-scan -A -M --trans="$enc,$hash,$auth,$grp" 203.0.113.50 2>/dev/null \
      | grep -q "Handshake returned" && echo "AGGR:  $enc,$hash,$auth,$grp"
   done; done; done; done | tee transforms-203.0.113.50.txt
```

3. Widen hash (4,5,6) and group (19,20,21) if nothing hits.
4. Multiple `--trans` options in one command send one multi-transform
   proposal; some gateways accept the multi-proposal but not singles —
   try both.
5. Record every accepted combo. Report as weak-crypto when enc=1 (DES),
   hash=1 (MD5), or group=1/2 is accepted. auth=1 or 65001 accepted ⇒ PSK
   attack path (aggressive-mode capture, or main-mode offline attack if you
   can MitM).

A full exhaustive sweep (`--trans` over the whole value space) can also be
scripted; the common space above finds >95% of real gateways.

## Vendor ID (VID) fingerprinting

VIDs are MD5 hashes of vendor strings. Common sightings:

| VID (hex prefix) | Implementation |
|---|---|
| `4048b7d56ebce885...` | IKE Fragmentation capability |
| `1f07f70eaa6514d3...` | Cisco Unity (ASA / IOS EasyVPN) |
| `09002689dfd6b712` | XAUTH supported |
| `afcad71368a1f1c9...` | Dead Peer Detection v1.0 |
| `4a131c81070358455c5728f20e95452f` | RFC 3947 NAT-T |
| `1e2b516905991c7d7c96fcbfb587e461...` | Windows (version in trailing bytes) |
| `f4ed19e0c114eb516faaac0ee37daf2807b4381f` | Fortinet FortiGate |
| `f4ed19e0c114eb51...` (other tails) | Fortinet family |
| `882fe56d6fd20dbc2251613b2ebe5beb` | strongSwan |
| `4f45...` (`OE..`) | Openswan/Libreswan (OE prefix) |
| `166f932d55eb64d8e4df4fd37e2313f0d0fd8451` | Netscreen/Juniper |
| `f758f22668750f03b08df6ebe1d0...` | Check Point (encodes version) |

`ike-scan -M` prints the decode in parentheses when the VID is in its
database; unknown VIDs are still worth googling/greping `ike-vendor-ids` in
the ike-scan source. Cisco Unity + XAUTH together ⇒ EasyVPN remote-access:
expect group-ID-gated aggressive mode; harvest/guess group names (company
name, "vpn", "remote", AD group names).

## Backoff fingerprinting (--showbackoff)

IKE has no application-layer ACK for the first message, so implementations
retransmit on vendor-specific schedules. `--showbackoff[=<ms>]` keeps
listening (default 60s extra) and diffs reply timestamps against the pattern
file (`ike-backoff-patterns`):

| Pattern shape (seconds between retransmits) | Guess |
|---|---|
| 0, 2, 4, 8, 16, 32 (6 msgs, doubling) | Linux FreeS/WAN / Openswan / strongSwan family |
| 0, 8, 8, 8 ... (fixed 8s) | Cisco VPN Concentrator |
| 0, 15, 15 ... (fixed 15s, 2-3 msgs) | Cisco IOS / PIX class |
| 0, 10, 10 (fixed 10s) | Juniper/Netscreen |
| 0, 5, 5, 5 ... | Nortel Contivity |

Caveats: patterns need a handshake-returning transform; packet loss corrupts
timing; scan hosts serially (`--backoff` patterns per-host). Use VIDs first,
backoff as the tiebreaker, and `Implementation guess:` output verbatim as
evidence.

## psk-crack modes

Input file = the `-P/--pskcrack` capture (one line of colon-separated hex
parameters: g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r).

```bash
# Dictionary (default mode; default dict is psk-crack-dictionary)
psk-crack -d rockyou.txt capture.txt

# Brute force: all strings up to length 6 from a charset
psk-crack -b 6 capture.txt
psk-crack -b 8 -c '0123456789' capture.txt     # digits-only, len<=8

# Useful extras
psk-crack -u capture.txt      # username/ID shown
psk-crack -v -d dict.txt capture.txt
```

- Hash type (HMAC-MD5 vs HMAC-SHA1) is auto-detected from hash_r length
  (16 vs 20 bytes).
- Throughput ~1-3M candidates/s per core. For big keyspaces convert to
  hashcat: mode **5300** (IKE-PSK MD5) / **5400** (IKE-PSK SHA1) take the
  same colon-separated parameter line as input.
- Candidate PSK ideas: company name ± year, product names, "vpn"/"ipsec"
  variants, keyboard walks, the group ID itself.

## XAUTH follow-through

If auth=65001 (XAUTH-PSK) and you crack the group PSK:
1. Configure a client (vpnc or strongSwan) with gateway IP, group ID, group
   PSK. XAUTH user/pass prompt follows.
2. Brute-force XAUTH over the now-established phase 1 (slow, online), or run
   `fiked` with the cracked PSK to impersonate the gateway and capture real
   XAUTH credentials in cleartext from connecting clients.
3. With full creds: tunnel up, enumerate the internal network — hand off to
   host-discovery against the inner ranges.
