# rupu wiring — metadata-ssrf-pivot

Shared shapes come from the reporting pack — import these skills BY NAME, do not
re-invent them:

- **work-units** — canonical work-unit splitter shape (`{"id","title","targets","hints"}`,
  bare JSON array in a file).
- **coverage-assets** — recording assets with rupu's `assets.mark` tool.
- **finding-report** — recording verified issues with rupu's `findings.report` tool.

## Files this skill produces

- `out/metadata-raw.json` — every raw metadata response (evidence; also feed it
  and any user-data/startup-script loot into the `trufflehog` skill's
  filesystem mode).
- `out/credentials.json` — parsed credentials with export-ready lines.
- `out/work-units.json` — **bare JSON array** (content starts with `[`) of work
  units, one per stolen credential, directly consumable by rupu's `for_each:`.
- `out/assets.json` — asset list for `assets.mark`.

Work-unit shape:

```json
[
  {
    "id": "mdp-0000",
    "title": "AWS credentials for arn:aws:iam::123456789012:role/web-app-role via metadata service",
    "targets": ["arn:aws:iam::123456789012:role/web-app-role", "123456789012"],
    "hints": {
      "provider": "aws",
      "credential_type": "sts-session",
      "role": "web-app-role",
      "expiration": "2024-01-02T03:04:05Z",
      "cred_ref": "out/credentials.json#0",
      "source_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role",
      "via_ssrf": "true",
      "next_skill": "cloud-credential-enumeration"
    }
  }
]
```

The secret material stays in `credentials.json` (`cred_ref` points at the entry);
units carry identities/accounts so they dispatch cleanly.

## Workflow fan-out (`for_each:`)

```yaml
- id: pivot
  run: |
    python3 skills/metadata-ssrf-pivot/scripts/metadata_pivot.py \
      --provider aws --ssrf 'https://app.example.com/fetch?u={url}' -o out/
- id: fan-out
  read_file: out/work-units.json
  for_each: unit
  steps:
    - skill: cloud-credential-enumeration
      with:
        targets: "{{ unit.targets }}"
        hints: "{{ unit.hints }}"
```

## Lead-agent dispatch

```yaml
lead:
  read_file: out/work-units.json
  dispatch:
    over: units
    agent: cred-worker
    brief: >
      Stolen {{ unit.hints.provider }} credential {{ unit.title }}. Load it from
      {{ unit.hints.cred_ref }}, verify ({{ unit.hints.credential_type }}:
      sts get-caller-identity / az rest subscriptions / gcloud projects list),
      then run cloud-credential-enumeration. STS creds expire —
      re-steal via the same SSRF before {{ unit.hints.expiration }}.
```

## assets.mark — asset model

Per the **coverage-assets** skill, mark:

- `cloud-account` — AWS account id (identity doc / ARN), Azure tenant (`tid`
  claim), GCP project (SA email suffix).
- `principal` — the role / managed identity / service account the workload runs as.
- `compute-instance` — instanceId / vmId / instance name from the identity
  document or `/metadata/instance`.
- `public-endpoint` — the vulnerable application URL (the SSRF entry point).
- `secret` — each stolen credential (STS session, bearer token, ya29 token) and
  captured bootstrap data (user-data / startup-script).

`parse_metadata_creds.py --assets out/assets.json` pre-builds these entries.

## findings.report

Per the **finding-report** skill, file the chain as a verified finding:

- title: `SSRF to cloud credential theft: <app URL> -> <provider> metadata -> <identity>`
- severity: critical (workload identity compromise; adjust to the identity's power
  after cloud-credential-enumeration reports back)
- evidence: the exact SSRF request (template + substituted metadata URL), the raw
  metadata response (from `out/metadata-raw.json`), and off-box proof of use
  (`aws sts get-caller-identity` / subscriptions list / `gcloud projects list`
  output).
- contributing factors to call out: IMDSv1 enabled (`HttpTokens=optional`), hop
  limit > 1, over-privileged instance role, missing egress controls.

Separate findings for bonus loot: secrets found in user-data / startup-script
(route those through the `trufflehog` skill and its finding flow).

## Chain

Umbrella: `cloud-security`. Upstream: web-app exploitation that yields SSRF/RCE/
file-read, or any shell on a cloud workload. Downstream:
`cloud-credential-enumeration` for every credential in `out/work-units.json`;
`trufflehog` (filesystem mode) over `out/metadata-raw.json` and dumped bootstrap
data; loop back here from new footholds the enumeration opens.

— vulture (sand-ridge)
