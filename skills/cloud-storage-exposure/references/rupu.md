# rupu wiring — cloud-storage-exposure

Import these shared reporting-pack skills BY NAME (do not re-invent their shapes):

- **work-units** — canonical work-unit splitter shape (`{"id","title","targets","hints"}`,
  bare JSON array in a file).
- **coverage-assets** — record assets with rupu's `assets.mark` tool.
- **finding-report** — record verified exposures with rupu's `findings.report` tool.

## Work-units files produced here

- `out/work-units.json` — from `scripts/probe_storage.py`; one unit per
  ACCESSIBLE bucket/container (access level `listable` or better; `exists`-only
  targets are recorded as assets, not units).
- Candidate name lists from `scripts/permute_names.py` are plain text, not units;
  they are probe input.

Bare JSON array (content starts with `[`) so rupu's `for_each:` parses it directly:

```json
[
  {
    "id": "s3-example-prod-backups",
    "title": "S3 bucket example-prod-backups: anonymous listable+readable",
    "targets": ["s3://example-prod-backups"],
    "hints": {"provider": "s3", "access": "listable", "anonymous": "true",
              "writable": "false", "object_count": "412",
              "url": "https://example-prod-backups.s3.amazonaws.com/"}
  },
  {
    "id": "azure-exampleacct-public",
    "title": "Azure container exampleacct/public: anonymous writable",
    "targets": ["https://exampleacct.blob.core.windows.net/public"],
    "hints": {"provider": "azure", "access": "writable", "anonymous": "true",
              "writable": "true", "object_count": "37"}
  }
]
```

## Workflow fan-out

```yaml
- id: permute
  run: python3 skills/cloud-storage-exposure/scripts/permute_names.py --bases example,examplecorp -o out/candidates.txt
- id: probe
  run: python3 skills/cloud-storage-exposure/scripts/probe_storage.py --provider s3 --names-file out/candidates.txt --profile target --write-test -o out/work-units.json --assets out/assets.json
- id: read_units
  tool: read_file
  path: out/work-units.json
- id: exploit_each
  for_each: out/work-units.json
  do:
    prompt: >
      Using cloud-storage-exposure, fully assess {{item.targets[0]}}
      (provider {{item.hints.provider}}, access {{item.hints.access}}):
      complete the three-identity matrix, attempt ACL/policy/key escalation,
      exfiltrate high-value objects to loot/{{item.id}}/, run trufflehog on the
      loot, record assets and findings. Route any discovered credentials to
      cloud-credential-enumeration.
```

Lead-agent dispatch over the same units:

```yaml
- id: dispatch_buckets
  dispatch:
    units_file: out/work-units.json
    agent_prompt: >
      You own one storage work unit: {{unit.title}}. Follow the
      cloud-storage-exposure skill end to end: matrix, escalation, exfil,
      trufflehog handoff, assets.mark + findings.report.
```

## Assets (coverage-assets → `assets.mark`)

- storage stores: `assets.mark type=storage-bucket id=s3://example-prod-backups`
  (hints: provider, access, anonymous, writable, object_count, contains_secrets)
- the owning account when determinable:
  `type=cloud-account id=azure-storage-account:exampleacct`
- public endpoints: `type=public-endpoint id=https://exampleacct.blob.core.windows.net/public`
- secrets found in loot: `type=secret id=<identifier>` with
  `hints.source=s3://example-prod-backups/terraform.tfstate`

`probe_storage.py --assets out/assets.json` emits these records (including
`exists`-but-denied buckets for coverage); feed each to `assets.mark`.

## Findings (finding-report → `findings.report`)

Report every VERIFIED exposure with the exact reproduction command + raw probe
output as evidence:

- anonymous listable/readable store — high (critical if secrets/PII confirmed);
- anonymous or any-authenticated WRITABLE store — critical; include the PoC
  object key you uploaded;
- `AuthenticatedUsers` / `allAuthenticatedUsers` grants — high;
- ACL/policy/IAM takeover (`WRITE_ACP`, `PutBucketPolicy`,
  `storage.buckets.setIamPolicy`) — critical;
- exposed account keys / over-scoped long-lived SAS — critical;
- secrets confirmed in exfiltrated objects — severity of the secret, link the
  trufflehog result and the originating bucket.

## Chain-back

Umbrella: **cloud-security**. Known-resource input from **cloudfox** /
**aws-enumeration** / **azure-enumeration** / **gcp-enumeration** work-units.
Loot secrets → **trufflehog** → **cloud-credential-enumeration** (every new
credential re-enters the credential hub). Bucket IAM weaknesses that extend
beyond storage → **cloud-privilege-escalation**.
