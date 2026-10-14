# rupu wiring — assets.mark, findings.report asset, for_each pipelines, coverage goals

## Tool availability

`assets.mark` and `findings.report` (with its `asset` argument) are **injected
automatically** into every agent of an engagement run — whatever the agent's
`tools:` list says, no entry is needed. An engagement is active when:

- `rupu run --engagement-profile network …` (CLI run), or
- a workflow is started with `--engagement-profile <id>`, or
- an agentiflow declares `engagement_profiles: [network, web]`.

Without an active engagement, `assets.mark` **does not exist** and
`findings.report`'s `asset` is **ignored** — nothing reaches the ledger.
`rupu findings import` records no asset either. Composite profiles (`pentest`,
`mobile`) activate their member profiles' kinds too.

## Exact call shapes

### `assets.mark`

```json
{
  "kind": "network:service",
  "coordinates": [
    { "t": "host", "v": "198.51.100.20" },
    { "t": "port", "v": { "number": 8443, "proto": "tcp" } }
  ],
  "depth": "enumerated",
  "label": "198.51.100.20:8443 admin console"
}
```

- `kind` must be namespaced and owned by an active profile.
- `depth` must be a rung of that profile's ladder; a wrong rung errors and the
  message lists the ladder (use it to self-correct, e.g. `api` has no
  `crawled`).
- **Forward-only**: an asset at `exploited` marked `tested` stays `exploited`.
  The response carries `effective_depth` — the rung actually on record. If
  `effective_depth > depth` you sent, another agent has already gone deeper;
  skip redundant work.
- `label` is optional; the ledger keeps the existing label unless you pass a
  new one. Profile label templates are declarative and never rendered — an
  asset's label is whatever a caller passed, else its kind.

### `findings.report` with `asset`

Same tool a workflow `action: findings.record` step calls — identical schema
there:

```json
{
  "scope": "edge-sweep",
  "report": { "...": "complete finding report (see the finding-report skill)" },
  "asset": {
    "kind": "network:service",
    "coordinates": [
      { "t": "host", "v": "198.51.100.20" },
      { "t": "port", "v": { "number": 8443, "proto": "tcp" } }
    ],
    "label": "198.51.100.20:8443 admin console"
  }
}
```

Processing order:

1. **Route** by `kind` namespace → owning profile. Unowned kind → error naming
   the active profile set.
2. **Completeness** — every `required` check of the owning profile runs against
   the report + locator (under the `full` finding profile; `summary` skips
   this). Failure → finding rejected, error lists the failing checks' labels.
   Fix the report or locator and resubmit.
3. **Stamp** — a line is appended to `assets.jsonl` and streamed to the run's
   `coverage.jsonl` (so a coordinator collecting a remote unit receives it).
   Existing depth/parent/attributes are preserved; label updates if supplied.
   The finding record itself stores no asset id.

Because asset ids are `kind + sorted locator`, a finding's asset and an
earlier `assets.mark` with the same coordinates are the same ledger entry.

## Ledger mechanics

`.rupu/coverage/<target>/assets.jsonl` — append-only, one full asset per line
(`id`, `kind`, `parent?`, `locator`, `label`, `depth?`, `attributes`); on read
the last line per id wins. Remote units' asset lines arrive through the
coverage stream and merge into the coordinator, deduplicated by occurrence.
Control plane reads via `GET /api/assets`: **Security → Assets** (all
workspaces) and the agentiflow **Assets** tab (`?ws_id=` / `?target=`).

Operator inspection:

```bash
rupu coverage list
rupu coverage show  <target>
rupu coverage audit <target>
rupu coverage gap   <target>
rupu --format json coverage audit <target>    # feed to jq / pipelines
rupu --format csv  coverage runs  <target>
```

## Pipeline: work-units → assets.mark (for_each)

Upstream, the `work-units` skill writes a normalized JSON array of
`{id, title, targets, hints}` units to a file (e.g. `reports/units.json`).
`for_each:` JSON-parses any rendered value starting with `[`, and
`read_file()` sources it from the file the splitter wrote — deterministic, no
dependence on agent chat output.

### Variant A — each worker marks as it goes

```yaml
workflow: edge-assessment
steps:
  - id: split
    agent: splitter          # uses the work-units skill
    actions: []
    prompt: |
      Split the engagement scope into work units and write them as a JSON
      array of {id,title,targets,hints} to reports/units.json.

  - id: assess
    agent: service-tester
    actions: []
    for_each: "{{ read_file('reports/units.json') }}"
    max_parallel: 4
    prompt: |
      Work unit {{ item.id }} ({{ loop.index }}/{{ loop.length }}): {{ item.title }}.
      Targets: {{ item.targets | tojson }}  Hints: {{ item.hints | tojson }}

      FIRST, mark every target as an asset at the first rung with assets.mark
      (network:host for bare hosts at "discovered"; network:service with
      host + port for host:port targets). Then enumerate, test, and exploit —
      re-marking the SAME coordinates at "enumerated" / "tested" / "exploited"
      as you actually get there. Attach the asset to every findings.report.
      Before finishing, call coverage.status and close any gap in your unit.
```

### Variant B — pre-generate marks with the script, bulk-apply, then fan out

```yaml
steps:
  - id: split
    agent: splitter
    actions: []
    prompt: |
      Write the work units as a JSON array to reports/units.json.

  - id: seed_marks
    agent: marker
    actions: []
    prompt: |
      Run:
        python3 scripts/assets_from_inventory.py --profile network \
          --depth discovered reports/units.json -o reports/marks.json
      Then call assets.mark once for each payload in reports/marks.json,
      exactly as written. Report the count of marks applied.

  - id: assess
    agent: service-tester
    actions: []
    for_each: "{{ read_file('reports/units.json') }}"
    max_parallel: 4
    prompt: |
      Assess unit {{ item.id }}. Scope is pre-marked at "discovered";
      advance each asset's depth as you enumerate/test/exploit.
```

Variant B guarantees the ledger reflects the full scope *before* any work
starts, so `rupu coverage audit` and coverage goals see real denominators from
minute one.

### Fan-out over findings (depth backfill)

After the fact, you can advance assets from tagged findings:

```yaml
steps:
  - id: exploited
    action: findings.query
    with: { q: "tag:exploited", all: true }
  - id: backfill
    agent: marker
    for_each: "{{ (steps.exploited.output | fromjson).rows | tojson }}"
    prompt: |
      Finding {{ item.id }} ({{ item.location }}) is exploited. Re-mark its
      asset at depth "exploited" with assets.mark using the same coordinates
      recorded on the finding.
```

(`findings.query` / `findings.tag` need explicit `tools:` grants, unlike the
injected asset tools.)

## Agentiflow: engagement + coverage goals

```yaml
name: edge-pentest
engagement_profiles: [network, web]
goals:
  # 90% of all network:service assets must reach "tested"
  - coverage: { reach: 0.9, depth: tested, kinds: [network:service] }
  # every discovered web route must be at least crawled
  - coverage: { reach: 1.0, depth: crawled, kinds: [web:route] }
```

Goals measure the asset ledger: `reach` is the fraction of assets of the
listed `kinds` whose depth is at or beyond `depth` (forward-only ordering of
the ladder makes "at or beyond" well-defined). An unmarked target doesn't
count against the denominator — which is why Variant B's seed step matters:
seed first, so the goal measures the real scope, not just what agents happened
to touch.

## Siblings

- **`work-units`** (upstream): produces the normalized inventory this skill
  marks. Its `{id,title,targets,hints}` array is the native input of
  `scripts/assets_from_inventory.py`.
- **`finding-report`** (downstream): writes the `report` body that passes the
  owning profile's completeness checks. This skill supplies the `asset` block
  that routes and stamps it.
