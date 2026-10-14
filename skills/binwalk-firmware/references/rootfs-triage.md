# Rootfs triage checklist

Run from inside the extracted root (`squashfs-root/`, `ubifs-root/`, …).
Everything found here becomes rupu assets/findings and work units for the
`binary-triage` / `qiling-unicorn` skills — see `rupu.md`.

## 1. Boot path → what actually runs

```sh
cat etc/inittab                       # ::sysinit / ::respawn lines name daemons
ls -la etc/init.d/ etc/rc.d/ etc/rcS.d/ 2>/dev/null
grep -rE '^[^#]*(\&|start|daemon)' etc/init.d/ 2>/dev/null | less
cat etc/rc.local etc/rc.common 2>/dev/null
ls etc/hotplug.d/ etc/udev/ 2>/dev/null     # event-triggered scripts
```

A daemon not launched at boot (and not spawnable via inetd/hotplug/web UI) is
low priority no matter how buggy it is. Note launch arguments — config paths,
listen ports, debug flags.

## 2. Network daemons — the primary attack surface

```sh
# Known names
find . -type f \( -name '*httpd*' -o -name '*telnetd*' -o -name 'dropbear*' \
  -o -name 'dnsmasq*' -o -name '*upnp*' -o -name 'miniupnpd' -o -name 'boa' \
  -o -name 'goahead' -o -name 'lighttpd' -o -name 'mini_httpd' -o -name 'snmpd' \
  -o -name 'smbd' -o -name 'ftpd' -o -name 'tftpd' -o -name 'mosquitto' \
  -o -name '*tr069*' -o -name '*cwmp*' -o -name '*acsd*' -o -name '*netctrl*' \)
# Unknown vendor daemons: anything importing socket APIs
for f in bin/* sbin/* usr/bin/* usr/sbin/*; do
  strings -a "$f" 2>/dev/null | grep -qE '^(bind|socket|recvfrom|accept)$' && echo "$f"
done
cat etc/services etc/inetd.conf etc/xinetd.conf 2>/dev/null
```

Vendor-custom daemons (`acsd`, `netctrl`, `cfm`, `*mgmt*`) are where the
0-days live — standard components get patched, these don't.

## 3. Web root and CGI

```sh
ls -laR www/ web/ usr/www/ home/httpd/ 2>/dev/null | head -100
find . -path '*cgi-bin*' -type f -exec file {} \;    # ELF CGI = direct binary input
grep -rn 'system\|popen\|exec' www/ --include='*.php' --include='*.lua' \
  --include='*.sh' --include='*.asp' 2>/dev/null
```

ELF CGI binaries parse `QUERY_STRING`/`CONTENT_LENGTH`/POST bodies directly —
hand each to `binary-triage` with kind `cgi`. Also map the web server's auth:
`httpd.conf`, `.htpasswd`, hardcoded realm checks inside the httpd binary
itself (common in GoAhead/Boa forks: `grep -a 'Authorization' usr/sbin/httpd`).

## 4. setuid / capability surface

```sh
find . -perm -4000 -type f -exec ls -la {} \;
find . -perm -2000 -type f -exec ls -la {} \;
```

On single-user embedded roots everything runs as root anyway, but setuid
binaries matter when the device drops privileges (newer SDKs) or for
post-auth escalation from a web shell running as `nobody`.

## 5. Credentials, keys, certificates

```sh
cat etc/passwd etc/shadow etc/passwd- etc/shadow- 2>/dev/null
# crackable hashes: descrypt ($ absent, 13 chars) and md5crypt ($1$) fall fast
#   → hashcat -m 1500 / -m 500
grep -rn 'PRIVATE KEY' . 2>/dev/null
find . \( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12' \
  -o -name 'authorized_keys' -o -name '*host*key*' \) -type f
grep -rniE 'password[=: ]|passwd[=: ]|secret[=: ]|pwd[=: ]' etc/ www/ usr/etc/ \
  --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.xml' \
  --include='*.json' --include='*.sh' --include='*.lua' 2>/dev/null | grep -v '^\s*#'
strings -a bin/* sbin/* usr/sbin/* 2>/dev/null | grep -iE '^(admin|root):' | sort -u
find . -name '*.sample' -o -name 'default*.cfg' -o -name 'nvram*'   # factory defaults
```

Hardcoded Dropbear/SSL host keys are shared across the entire device fleet —
a finding on its own (traffic decryption, impersonation). Report credentials
and keys via `findings.report` immediately; do not wait for binary analysis.

## 6. Component versions → known CVEs

```sh
strings -a bin/busybox | grep -oE 'BusyBox v[0-9][0-9.]+'
strings -a usr/sbin/dropbear* 2>/dev/null | grep -oE 'Dropbear[ _a-zA-Z]*20[0-9]{2}\.[0-9]+'
strings -a usr/sbin/lighttpd 2>/dev/null | grep -oE 'lighttpd/[0-9.]+'
strings -a usr/sbin/uhttpd usr/sbin/boa usr/sbin/goahead usr/sbin/mini_httpd \
  2>/dev/null | grep -iE 'server:|version'
strings -a usr/sbin/dnsmasq 2>/dev/null | grep -oE 'dnsmasq-[0-9.]+'
strings -a lib/libssl* usr/lib/libssl* 2>/dev/null | grep -oE 'OpenSSL [0-9.]+[a-z]?'
strings -a usr/sbin/miniupnpd 2>/dev/null | grep -oE 'miniupnpd/[0-9.]+'
strings -a lib/libc.so* lib/libuClibc* 2>/dev/null | grep -iE 'uclibc|musl|glibc' | head
```

Check each hit against the CVE record (dnsmasq DNSpooq < 2.83, Dropbear
< 2016.74 CVE-2016-7406, OpenSSL 1.0.1 Heartbleed, miniupnpd < 1.4,
GoAhead CVE-2017-17562, Boa — unmaintained since 2005). Version + known CVE
= `findings.report` with the component path as evidence.

## 7. Architecture + libc (for emulation and exploitation)

```sh
file bin/busybox          # e.g. "ELF 32-bit MSB executable, MIPS, MIPS32..."
ls lib/ | head            # ld-uClibc, libc.so.0 (uClibc), musl, glibc?
readelf -h bin/busybox | grep -E 'Class|Data|Machine'
```

Record arch/endianness/libc per binary — it decides the qemu binary, the
Qiling rootfs profile, and later the ROP strategy (`binary-protections`
skill checks NX/RELRO/canary per binary).

## 8. Emulation handoff

Dynamically linked target, foreign arch:

```sh
# qemu-user: -L sets the ELF interpreter prefix to the extracted rootfs
qemu-mipsel-static -L . ./bin/busybox ls
qemu-mipsel-static -L . -strace ./usr/sbin/httpd      # syscall trace
qemu-arm-static -L . -g 1234 ./usr/sbin/upnpd &       # gdbserver on :1234
gdb-multiarch -ex 'target remote :1234' usr/sbin/upnpd
# full chroot (copy the static qemu in first)
cp "$(command -v qemu-mipsel-static)" . && chroot . /qemu-mipsel-static /bin/sh
```

Daemons that touch NVRAM (`nvram_get`/`libnvram.so`) crash under plain qemu —
preload a fake (`firmadyne/libnvram`) or move to **Qiling**: load the
`qiling-unicorn` skill and point it at the rootfs
(`Qiling(["squashfs-root/usr/sbin/httpd"], rootfs="squashfs-root")`) to hook
nvram/ioctl and fuzz with coverage. Whole-system options when userland
emulation isn't enough: firmadyne / FirmAE / `qemu-system-mips` with a kernel
matching the vendor's.

## 9. Prioritization order

1. CGI ELF binaries and the HTTP daemon (pre-auth, remote).
2. Init-launched vendor daemons binding sockets (UPnP, TR-069/CWMP, custom mgmt).
3. Services parsing broadcast/link-local input (dnsmasq, snmpd, mdns).
4. Credential/key findings (report now, zero reversing cost).
5. setuid binaries and local parsers (escalation / chained use).

Emit one work unit per item (script does this) and fan out with
`binary-triage`.
