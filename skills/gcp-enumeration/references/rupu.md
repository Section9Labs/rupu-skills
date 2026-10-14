# rupu Wiring — gcp-enumeration

This skill's parse step always ends by writing `out/work-units.json` — a **bare
JSON array** (file content starts with `[`) of
`{"id","title","targets","hints"}` objects, produced by
`scripts/gcp_to_work_units.py`. That is the only contract rupu needs.

Import the shared reporting-pack skills BY NAME — do not re-implement them:

- **`work-units`** — canonical splitter shape (`id`/`title`/`targets`/`hints`),
  file conventions, dedup rules.
- **`coverage-assets`** — recording discovered assets with rupu's `assets.mark`.
- **`finding-report`** — recording verified issues with rupu's `findings.report`.

## Fan-out over work units

Workflow `for_each:` JSON-parses a file whose content starts with `[`:

```yaml
steps:
  - id: gcp-enum
    run: |
      python3 scripts/gcp_enum.py --all-projects -o out/gcp-inventory.json
      python3 scripts/gcp_to_work_units.py out/gcp-inventory.json \
        -o out/work-units.json --assets out/assets.json
  - id: exploit-unit
    for_each:
      file: out/work-units.json
    prompt: |
      Work unit: {{item.title}} (id {{item.id}})
      Targets: {{item.targets}}
      Hints: {{item.hints}}
      Follow the gcp-enumeration handoffs for this unit type (hints.kind):
      bucket -> cloud-storage-exposure; secret -> `gcloud secrets versions
      access` then trufflehog; instance -> metadata/serial loot, token theft
      (metadata-ssrf-pivot); sa_actas -> impersonation / key minting
      (cloud-privilege-escalation); gke -> get-credentials + k8s flow;
      public_endpoint/cloudsql -> network/db attack surface; function/run ->
      env + source dump -> trufflehog.
```

A lead agent dispatches over the same array:

```
read_file out/work-units.json
dispatch(units, worker_skill="gcp-enumeration",
         instructions="one unit per worker; report assets and findings via rupu tools")
```

## Asset model (`assets.mark`)

Mark everything the sweep proves to exist, per `coverage-assets`:

| kind | id convention | example |
|---|---|---|
| cloud account | `gcp:project:<projectId>` (and `gcp:org:<orgId>`) | `gcp:project:project-id-1` |
| principal/role | `gcp:sa:<email>` / `gcp:principal:<member>` + role in attrs | `gcp:sa:ci-build@project-id-1.iam.gserviceaccount.com` |
| compute instance | `gcp:instance:<project>/<zone>/<name>` | `gcp:instance:project-id-1/us-central1-a/web-01` |
| storage bucket | `gcs:<bucket>` | `gcs:example-bucket` |
| public endpoint | `ip:<addr>` / `url:<https url>` | `ip:198.51.100.20`, `url:https://svc1-abc-uc.a.run.app` |
| secret | `gcp:secret:<project>/<name>` | mark on confirmed `versions access` |

`gcp_to_work_units.py --assets out/assets.json` emits ready
`{kind,id,attrs}` records to loop through `assets.mark`.

## Findings (`findings.report`)

Report via `finding-report` when verified (actual read/exec/impersonation, not
just listed):

- bucket readable by `allUsers`/`allAuthenticatedUsers` (and what it contained)
- Secret Manager values readable by the current (low-priv) principal
- SA key minted or token generated via impersonation (include the chain)
- credentials found in startup scripts / env vars / serial output / build logs
- instance SA with `cloud-platform` scope reachable from a foothold
- Cloud SQL / GKE master exposed to 0.0.0.0/0
- privesc-grade permission confirmed by testIamPermissions
  (setIamPolicy, serviceAccountKeys.create, cloudbuild.builds.create, ...)

Include the exact `gcloud`/`curl` command and output excerpt as evidence, the
asset id, and the handoff skill that continues exploitation.

## Chain

Umbrella: `cloud-security`. Siblings: `cloud-privilege-escalation`,
`cloud-storage-exposure`, `trufflehog`, `metadata-ssrf-pivot`.
