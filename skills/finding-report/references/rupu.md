# rupu wiring — recording, profiles, assets, tags, exports

## Record once, render everywhere

A finding is recorded **once**, as structured data. That record is the source
of truth: rupu generates the control-plane views and the Markdown/HTML/PDF
exports from it. Never write a separate report file.

```
rupu findings schema                      # print the exact report JSON Schema
rupu findings export --to md              # export findings (also: html, pdf)
```

## The tool on each surface

The same tool, three surfaces:

1. **Agent tool** — `findings.report` (aliases: `findings.record`,
   `report_finding`). Injected automatically when the agent has a `concerns:`
   block; otherwise grant it in the agent's `tools:`. In an engagement run it
   is offered to every agent regardless of `tools:`.

```json
{
  "report": { "…": "complete report object — see field-reference.md" },
  "scope": "edge-sweep",
  "asset": {
    "kind": "network:service",
    "coordinates": [
      {"t": "host", "v": "198.51.100.20"},
      {"t": "port", "v": {"number": 8443, "proto": "tcp"}}
    ],
    "label": "198.51.100.20:8443 admin console"
  },
  "tags": ["exposed-admin", "tls"]
}
```

2. **Workflow step** — `action: findings.record`:

```yaml
- name: record-sqli
  action: findings.record
  findings_profile: full        # optional; see precedence below
  with:
    scope: "edge-sweep"
    report:
      title: "Unauthenticated SQL injection in product search on shop.example.com"
      # … every required field …
    asset:
      kind: "api:endpoint"
      coordinates:
        - { t: "url", v: "https://shop.example.com" }
        - { t: "http_route", v: { method: "GET", path: "/api/v1/search" } }
        - { t: "param", v: "q" }
      label: "shop.example.com GET /api/v1/search?q"
    tags: ["sqli", "api"]
```

3. **MCP** — `rupu mcp serve` exposes the same tool to any MCP client; identical
   arguments and validation.

A remote workflow unit (`host:` / `distribute:`) runs `findings.report` on the
host; its artifacts land in that host's store (`stored: external` with `host`
set on the coordinator) and its coverage/finding lines stream back via
`coverage.jsonl`.

## full vs summary profile

| Profile | Accepts |
|---|---|
| `full` (default) | a complete `report` object. Top-level `summary`, `severity`, `evidence` are **rejected** — rupu derives them: `summary` ← `title`, `severity` ← `rating.risk_rating`, evidence rationale ← `root_cause`. |
| `summary` | the lightweight `summary` / `severity` / `evidence` record. A `report` is **refused**, never silently dropped. |

Chosen by (highest precedence first): workflow step `findings_profile` or
`rupu run --findings-profile` → workflow `defaults.findings_profile` → agent
frontmatter `findingsProfile` → built-in `full`. Remote units receive the
resolved value as `--findings-profile`. The profile is stamped on each stored
record; pre-profile records read back as `summary`. This skill always targets
`full`.

When a full-profile run can record findings, rupu appends finding-writing
guidance to the agent's system prompt — this skill is the deeper methodology on
top of that.

## The `asset` argument (engagement profiles)

Only meaningful when an engagement is active (otherwise ignored). `kind` must
be namespaced (`network:service`, `web:route`, `api:endpoint`,
`binary:function`, `code:file`, `cloud:resource`, …); the namespace routes the
finding to the owning profile, which:

1. **Validates completeness** — every `required` check of that profile runs
   against the report + locator; failures reject the finding and name each
   failing check. Key ones:
   - `network`: locator has `host` **and** `port`; `root_cause` filled; a CVE or CWE classification.
   - `web`: `http_route` or `url`; an `http_exchange` evidence block; OWASP or CWE.
   - `api`: `http_route`; an `http_exchange` evidence block.
   - `code`: `path`; `root_cause`. `binary`/`firmware`: a `disasm`/`hexdump` (or `decompile`) block; CWE.
   - `cloud`: `resource_id`; CIS or CWE. `sca`: purl `resource_id`; CVE or GHSA.
     `redteam`: an ATT&CK classification; `description` filled.
2. **Stamps the asset** into `assets.jsonl` (same id for the same kind+locator
   across reruns; label updated only if supplied).

Coordinates are typed `{"t": <tag>, "v": <value>}` pairs: `path`,
`line_range {start,end}`, `symbol`, `commit`, `sha256`, `offset`, `address`,
`host`, `port {number, proto: tcp|udp|other}`, `url`,
`http_route {method, path}`, `param`, `resource_id {scheme, id}`.

An engagement active but no `asset` on the call → recorded on the plain path,
no completeness check. Separately, record examination depth with
`assets.mark` (`{"kind": "web:route", "coordinates": […], "depth": "exploited"}`);
depth only moves forward along the profile's ladder.

## Classifications, tags, cross-references

- `report.classifications[]` — `{system, id, vector?}` for CVE / ATT&CK /
  OWASP / CIS / GHSA / STRIDE entries, additive to `cwe`. Several profile
  checks are satisfied by these (e.g. `network`'s `classified` by a CVE or CWE
  entry; `redteam`'s `mapped_to_attack` by an ATT&CK entry).
- `tags` — array on the `findings.report` call; later, `findings.tag` (explicit
  `tools:` grant) adds/removes tags on one or many findings and returns
  before/after. `findings.query` (explicit grant) searches recorded findings
  and returns slim rows + `tags_in_use` — use it to find `fnd_` ids for
  cross-referencing.
- `cross_references` — inside the report: `"None"` or
  `[{"finding_id": "fnd_…", "relation": "prerequisite", "note": "…"}]`. The id
  is what a previous `findings.report` call returned, and must exist.

## Artifacts and evidence-block files

- `report.artifacts[].path`: workspace-relative PoC files; supply only `path`.
  rupu hashes each: ≤ 500 MiB → copied into the content-addressed store
  (`stored: copied`, deduplicated across runs); larger → recorded
  `stored: external` by reference. Directories expand (symlinks skipped).
  Per report: ≤ 500 files, ≤ 2 GiB copied (defaults) — list specific files, not
  big directories. A path that escapes the workspace, is `.`, doesn't exist, or
  isn't a regular file rejects the finding.
- `image` / `hexdump` / `pcap_ref` blocks name exactly one file in
  `artifact.path`, stored under the same rules and shared limits; a bad path
  rejects at `report.blocks[<i>].artifact.path`. Block files are not listed as
  PoC artifacts but render in the finding page's Evidence blocks section.
- Evidence claims' `sha256` is taken by rupu from the claim's `file` (inside
  the workspace, ≤ artifact cap); otherwise stored without a hash.
- Download later via `GET /api/findings/:id/artifacts/:sha256` or the finding
  page's artifact browser; remote (`external` + `host`) blobs are pulled from
  their host on first access.

## Error handling and limits

- A rejected `findings.report` call returns **every** problem at once, each
  with its field path — fix all, retry once. Malformed JSON → single parse
  error.
- Serialized report ≤ 256 KiB default (`[findings].report_max_bytes`),
  re-checked after directory expansion. Excerpt in `evidence`, full capture as
  an artifact.
- `verification` is never sent by the reporting agent; verification runs set
  `{status: unverified|confirmed|disputed|inconclusive, by_run?, notes?}` later.

## Inspection after recording

```
rupu coverage show <target>        # files touched + assertions + findings
rupu coverage audit <target>       # per-concern coverage, gaps, serendipitous findings
rupu findings export --to pdf      # client deliverable
```
