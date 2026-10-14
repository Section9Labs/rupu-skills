"""harvest_addon.py — mitmproxy addon: harvest every endpoint + parameters to JSONL.

This file is a mitmproxy ADDON — it needs the mitmproxy runtime:

    mitmdump -s scripts/harvest_addon.py --set harvest_file=harvest.jsonl -w capture.mitm
    mitmdump -nr capture.mitm -s scripts/harvest_addon.py --set harvest_file=harvest.jsonl

Each flow produces one JSON line:
  {"method","url","host","scheme","path","status","ctype",
   "query":{name:example}, "form":{name:example}, "json_keys":[...], "ts":...}

Normalize/dedupe the JSONL with the standalone stdlib parser:
    python3 scripts/flows_to_targets.py harvest.jsonl -o endpoints.json \
        --work-units wu.json --assets assets.json --depth crawled

-- vulture (wine-crag)
"""

import json
import sys
import time

try:
    from mitmproxy import ctx, http  # noqa: F401
    _HAVE_MITMPROXY = True
except ImportError:
    _HAVE_MITMPROXY = False


class Harvester:
    def __init__(self):
        self.fh = None

    def load(self, loader):
        loader.add_option(
            "harvest_file", str, "harvest.jsonl",
            "Path of the JSONL file to append harvested endpoint records to.",
        )
        loader.add_option(
            "harvest_bodies", bool, False,
            "Also record (truncated) request bodies for non-form content types.",
        )

    def configure(self, updates):
        if "harvest_file" in updates:
            if self.fh:
                self.fh.close()
            self.fh = open(ctx.options.harvest_file, "a", buffering=1)
            ctx.log.info("harvest_addon: writing to %s" % ctx.options.harvest_file)

    def done(self):
        if self.fh:
            self.fh.close()
            self.fh = None

    def response(self, flow):
        self._emit(flow)

    def error(self, flow):
        # still record the request even if the upstream leg failed
        self._emit(flow)

    def _emit(self, flow):
        if not self.fh:
            return
        req = flow.request
        rec = {
            "ts": time.time(),
            "method": req.method,
            "url": req.pretty_url,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path.split("?", 1)[0],
            "status": flow.response.status_code if flow.response else None,
            "ctype": (flow.response.headers.get("content-type", "").split(";")[0].strip()
                      if flow.response else None),
            "req_ctype": req.headers.get("content-type", "").split(";")[0].strip(),
            "query": {k: req.query[k] for k in req.query.keys()},
            "form": {},
            "json_keys": [],
        }
        try:
            rec["form"] = {k: req.urlencoded_form[k] for k in req.urlencoded_form.keys()}
        except Exception:
            pass
        if "json" in rec["req_ctype"]:
            try:
                body = req.json()
                if isinstance(body, dict):
                    rec["json_keys"] = sorted(body.keys())
            except Exception:
                pass
        if getattr(ctx.options, "harvest_bodies", False) and req.content and not rec["form"]:
            try:
                rec["body"] = req.get_text(strict=False)[:2048]
            except Exception:
                pass
        self.fh.write(json.dumps(rec) + "\n")


if _HAVE_MITMPROXY:
    addons = [Harvester()]


if __name__ == "__main__":
    sys.stderr.write(
        "harvest_addon.py is a mitmproxy addon, not a standalone script.\n"
        "Run it inside mitmdump:\n\n"
        "  mitmdump -s scripts/harvest_addon.py --set harvest_file=harvest.jsonl -w capture.mitm\n"
        "  mitmdump -nr capture.mitm -s scripts/harvest_addon.py --set harvest_file=harvest.jsonl\n\n"
        "Then parse the JSONL with: python3 scripts/flows_to_targets.py harvest.jsonl --work-units wu.json\n"
    )
    sys.exit(2)
