# rupu wiring: read_file + for_each, dispatch fan-out, and the handoff rule

How work-unit arrays plug into rupu workflows and fleet leads. The scripts in
this skill exist to feed these three patterns.

## 1. `read_file` + `for_each` — the canonical workflow fan-out

rupu's `for_each:` renders its template to text. **If the rendered text starts
with `[`, rupu parses it as a JSON/YAML array**; otherwise it treats each
non-empty line as one item. That is why the splitter's output rule is absolute:
`reports/units.json` must be exactly one clean JSON array — the file content
*is* the `for_each` value via `read_file()`.

`read_file` makes control flow depend on a **file a prior step wrote**, not on
an agent's chat output — far more deterministic. The agent's final message is
irrelevant; only the file matters.

### Full two-step workflow: normalize, then fan out

```yaml
steps:
  # Step 1 — map/normalize: run the scanners, end by writing the unit array.
  - id: map_attack_surface
    agent: recon-operator
    prompt: |
      Map the attack surface of example.com (203.0.113.0/24).
      Run, in order, saving machine output under reports/:
        naabu -host example.com -top-ports 1000 -json -silent -o reports/ports.jsonl
        httpx  -l <(cut -d: -f1 reports/ports.jsonl | sort -u) -json -silent \
               -title -tech-detect -o reports/web.jsonl
        nmap -sV -sC -oX reports/scan.xml 203.0.113.10-50
      Then normalize everything into ONE work-unit array:
        python3 skills/work-units/scripts/split.py naabu reports/ports.jsonl -o reports/u-naabu.json
        python3 skills/work-units/scripts/split.py httpx reports/web.jsonl   -o reports/u-httpx.json
        python3 skills/work-units/scripts/split.py nmap  reports/scan.xml    -o reports/u-nmap.json
        python3 skills/work-units/scripts/merge.py reports/u-naabu.json \
                reports/u-httpx.json reports/u-nmap.json -o reports/units.json
      reports/units.json MUST be a clean top-level JSON array and nothing else.

  # Step 2 — worker fan-out: one agent run per work unit.
  - id: attack_each_service
    agent: service-attacker
    for_each: "{{ read_file('reports/units.json') }}"
    max_parallel: 4
    prompt: |
      Work unit {{ item.id }} ({{ loop.index }} / {{ loop.length }})
      Title:   {{ item.title }}
      Targets: {{ item.targets | tojson }}
      Hints:   {{ item.hints | tojson }}

      Enumerate and exploit this unit. Use the hints (service, product,
      version, tech, scripts) to pick techniques; do not re-scan what the
      hints already tell you. Write results to reports/{{ item.id }}/.
```

### Per-item template variables

Inside the fanned-out step each unit's fields address directly:

- `{{ item.id }}`, `{{ item.title }}`, `{{ item.targets }}`, `{{ item.hints }}`
- deep access works: `{{ item.hints.product }}`, `{{ item.targets[0].value }}`
- loop context: `{{ loop.index }}`, `{{ loop.index0 }}`, `{{ loop.length }}`,
  `{{ loop.first }}`, `{{ loop.last }}`

### The `| tojson` rule

When a list of objects comes from a **step output** rather than a file, render
it with `| tojson` so `for_each` receives an exact JSON array instead of
whatever the template engine prints for a Python list:

```yaml
for_each: "{{ (steps.tagged.output | fromjson).rows | tojson }}"
```

Same rule inside prompts: embed `{{ item.targets | tojson }}` /
`{{ item.hints | tojson }}` so the child agent gets parseable JSON, not a
repr. `read_file('reports/units.json')` needs no `| tojson` — the file already
contains literal JSON text.

### Splitter as a bash step

If the workflow has `bash`-capable steps, run the splitter directly instead of
asking an agent to do it:

```yaml
  - id: normalize
    bash: |
      python3 skills/work-units/scripts/split.py nmap reports/scan.xml -o reports/units.json
```

Deterministic normalization beats prompting an agent to "write JSON" every time.

## 2. Lead-agent `dispatch` fan-out

A fleet lead that reads `reports/units.json` can fan out children itself with
the `dispatch` tool — one call per unit, kind `agent`, `workflow`, or
`subagent` — embedding the unit's targets and hints in each child's prompt:

```json
{
  "kind": "agent",
  "name": "service-attacker",
  "prompt": "Work unit service-203-0-113-20-8443-tcp-9f2c41ab: 203.0.113.20:8443/tcp https (nginx 1.18.0)\nTargets: [{\"type\":\"host\",\"value\":\"203.0.113.20\"},{\"type\":\"service\",\"value\":\"203.0.113.20:8443\",\"host\":\"203.0.113.20\",\"port\":8443,\"protocol\":\"tcp\"}]\nHints: {\"service\":\"https\",\"product\":\"nginx\",\"version\":\"1.18.0\",\"source\":\"nmap\"}\nEnumerate and exploit; write findings for unit id service-203-0-113-20-8443-tcp-9f2c41ab."
}
```

Lead-agent loop shape:

1. Read `reports/units.json` (it is a JSON array — parse, don't scrape).
2. For each unit, `dispatch` a child whose prompt contains `id`, `title`, and
   the JSON of `targets` and `hints`. Always pass the `id` through — children
   name their output directories and findings after it, which is what makes
   results joinable afterwards.
3. Optionally batch: group units by `hints.service` or `targets[].host` and
   dispatch one child per group when per-unit children would be too many.

In workflow YAML, the same fan-out can place units across hosts with
`for_each` + `distribute:` so each unit's worker lands on an execution host
near the target:

```yaml
  - id: attack_each
    agent: service-attacker
    for_each: "{{ read_file('reports/units.json') }}"
    distribute: round_robin
    max_parallel: 8
    prompt: |
      {{ item.title }} — targets {{ item.targets | tojson }}, hints {{ item.hints | tojson }}
```

## 3. The handoff rule (what every other pack does)

**Every parse step ends by writing a work-unit array with this splitter.**
Recon packs end their nmap/naabu/httpx steps with `split.py` + `merge.py`;
API packs end spec analysis with `split.py openapi`; code-review packs end
with `split.py sarif`; cloud packs end with `split.py prowler`. The next
phase — enumeration, exploitation, reporting — always consumes
`{id,title,targets,hints}`, never raw scanner output. One contract, one
parser, zero per-pack glue.

Downstream consumers, imported by name:

- **`coverage-assets`** — feeds the same units/inventory to `assets.mark` so
  the control plane tracks which units have been covered. Unit `targets`
  map 1:1 onto asset entries; the unit `id` is the natural asset correlation
  key.
- **`finding-report`** — when a worker verifies an issue on a unit, it records
  it with `findings.report`, carrying the unit `id` (and the `hints` raw
  reference) in the finding so the report links back to the exact work unit
  and its source-tool evidence. A later `findings.query ... all: true` step
  can then itself drive a `for_each` (e.g. PoC writing per finding) with the
  same `| tojson` pattern shown above.

Chain picture:

```
scanner output ──split.py──▶ units.json ──for_each/dispatch──▶ workers
                                   │                              │
                                   ├──▶ coverage-assets (assets.mark)
                                   └──────────────────────▶ finding-report (findings.report)
```
