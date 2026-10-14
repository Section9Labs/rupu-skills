# rupu wiring for binwalk-firmware

This skill parses binwalk output and a rootfs tree, so it must end in
rupu-ingestible data: work units (file), assets (`assets.mark`), findings
(`findings.report`), evidence (workspace files). Import the shared
`work-units` and `finding-report` skills by name — do not reinvent their
contracts.

## Work units — `work-units.json`

`scripts/firmware_triage.py` writes `<outdir>/work-units.json`: a **clean JSON
array** (file content starts with `[`, so rupu `for_each:` can JSON-parse it
directly). One unit per high-value binary:

```json
[
  {
    "id": "usr-sbin-httpd",
    "title": "Triage httpd (network-daemon, MIPS LSB) from squashfs-root/usr/sbin/httpd",
    "targets": [
      {
        "file": "/work/triage-out/rootfs/squashfs-root/usr/sbin/httpd",
        "rootfs_path": "usr/sbin/httpd",
        "kind": "network-daemon",
        "version": "lighttpd/1.4.32"
      }
    ],
    "hints": ["binary-protections", "binary-triage", "qiling-unicorn"]
  }
]
```

Contract (exactly these keys, per the shared `work-units` skill):
- `id` — stable lowercase `[a-z0-9-]` slug of the rootfs-relative path.
- `title` — human-readable, names binary + kind + arch.
- `targets` — non-empty; each target carries the absolute extracted `file`,
  the `rootfs_path` relative to the rootfs root, `kind` one of
  `network-daemon` | `setuid` | `cgi` | `other`, and `version` (component
  version string or `null`).
- `hints` — **sorted** array of next skills: `binary-protections`,
  `binary-triage`, `qiling-unicorn` for daemons/CGI; static-only binaries
  drop `qiling-unicorn`.

Fan-out example (generic mechanics in the `work-units` skill):

```yaml
for_each: triage-out/work-units.json
run: binary-triage
```

## Assets — `assets.mark`

Depth ladder for `binary:file` is monotonic:
`discovered → triaged → analyzed → vuln-identified → exploited`.

- The firmware image itself: `binary:file`, coordinate `t=file,
  v=sha256(firmware.bin)`, mark `discovered` (stays `discovered` if encrypted
  and blocked on key recovery — note the blocker in the asset note).
- Every ELF inventoried from the rootfs: `binary:file` with `t=file,
  v=<sha256>` (path in the note), mark `discovered`. This skill never promotes
  past `discovered` — `binary-triage` promotes to `triaged`/`analyzed`,
  vuln-hunting skills to `vuln-identified`, exploitation to `exploited`.
- Interesting functions/sinks found later (e.g. a `system()` xref in a CGI):
  `binary:symbol` with the file coordinates plus `t=symbol` name or `t=vaddr`
  — that's `binary-triage`'s job, listed here only so the model stays
  consistent across the pack.

## Findings — `findings.report`

Use the shared `finding-report` skill's field contract. Report from this
stage (no binary analysis required):

- Hardcoded credentials: `/etc/passwd`/`/etc/shadow` hashes, `password=` in
  configs — severity by exposure (telnet/web login creds = high).
- Embedded private keys / fleet-shared TLS or SSH host keys (`PRIVATE KEY`
  matches, `*.pem`, dropbear host keys).
- CVE-bearing component versions (BusyBox, Dropbear, lighttpd, dnsmasq,
  OpenSSL, miniupnpd …): finding per component, version string + binary path
  + CVE IDs as evidence.

Everything else (memory corruption, command injection in daemons) is reported
by the downstream skills, not here.

## Evidence — keep everything

Under the run workspace, never deleted:
- raw binwalk logs (`binwalk.sig.txt`, `binwalk.entropy.txt`, v3 JSON logs),
- the full extraction tree (`_firmware.bin.extracted/` / `extractions/`),
  with the **carved root filesystem recorded as evidence** attached to the
  firmware-image asset (path + sha256 of the carved squashfs blob),
- `triage-report.txt` and `work-units.json` from the script.

Downstream findings reference these paths; re-extraction is never free
(vendor extractors are flaky), so the tree is the ground truth.
