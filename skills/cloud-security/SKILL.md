---
name: cloud-security
description: Umbrella router for offensive cloud-security assessment across AWS, Azure (incl. Entra ID), and GCP — runs the credential→identity→posture→enumeration→privesc→loot→new-credential loop and routes each phase to the right sub-skill by name.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# Cloud Security — Umbrella / Router

This is the entry point for the offensive cloud assessment pack. It does not run
tools itself; it tells you **which sub-skill to load at each phase** and how the
phases chain. Load the named sub-skill, follow it, come back here with its
outputs, continue the loop.

## The loop

Providers differ in syntax; the loop is identical everywhere:

```
credential → whoami/identity → posture scan → resource & attack-surface map
    → IAM graph & privilege escalation → loot (storage, secrets, data)
    → NEW credentials → repeat (every new credential re-enters at whoami)
```

The loop terminates only when a full pass produces **zero new credentials and
zero new principals**. Treat every credential as a node in a graph; the edges
are "this credential can obtain that credential" (privesc paths, secrets in
storage, metadata endpoints, role assumption). Full discipline:
`references/methodology.md`.

## Framing (brief)

- **MITRE ATT&CK**: there is no standalone "Cloud" matrix anymore — use the
  Enterprise matrix (v18, late 2025) filtered to the **IaaS / Identity
  Provider / SaaS / Office Suite** platforms. In practice: credential abuse
  (T1078.004 Valid Accounts: Cloud) is the dominant initial vector, followed by
  Cloud Instance Metadata API abuse (T1552.005), Impair Defenses / disable
  cloud logging (T1562.008), and Data from Cloud Storage (T1530).
- **CIS Benchmarks**: AWS / Azure / GCP **Foundations Benchmarks** are the
  posture baseline every scanner in phase 2 maps its checks to. A failed CIS
  control is a lead, not a finding — chase it to exploitation in phases 3–7.

The phase→ATT&CK→CIS mapping table is in `references/methodology.md`.

## Phase 1 — Credential discovery & identity

Load **`cloud-credential-enumeration`**.

Recognize what you're holding before anything else:

| Material | Looks like | Provider |
|---|---|---|
| Access key | `AKIA...` (long-lived) / `ASIA...` + session token | AWS |
| Service principal | client_id + client_secret + tenant_id, or cert | Azure |
| SAS URL | `?sv=...&sig=...` on a blob/container URL | Azure |
| JWT access token | `eyJ...` with `aud` = management/graph | Azure/Entra |
| SA key JSON | `{"type":"service_account", "private_key":...}` | GCP |
| OAuth token | `ya29....` | GCP |
| CLI state | `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/` | all |

Then **whoami** on every credential, every time:

```
aws sts get-caller-identity
az account show && az ad signed-in-user show
gcloud auth list && gcloud config get-value project
```

Record the identity (account/tenant/project, principal ARN/objectId/email)
before spending any API calls. A credential whose identity you haven't recorded
is a credential you'll lose track of.

## Phase 2 — Posture assessment

Pick by what you need; running two is normal:

- Load **`prowler`** — check-based scanner, CIS/compliance mappings, OCSF JSON
  output. Default breadth pass; its findings file is the seed for work units.
- Load **`scoutsuite`** — builds a browsable per-service HTML model of the
  environment. Best when you want to *read* the environment, not just list
  failures.
- Load **`cloudsploit`** — plugin scanner, lightweight, JSON/CSV output, good
  for CI-style repeat runs and diffing between loop iterations.
- Load **`steampipe`** — ad-hoc SQL over live cloud APIs plus packaged CIS
  benchmark mods. Use when you have a specific question ("all buckets with a
  policy containing `Principal: *`") rather than a scan.

Posture output answers "where is this environment weak"; it does **not**
replace enumeration. Carry high-value failures (public storage, wildcard IAM,
disabled logging, open security groups) into phases 3–7 as work units.

## Phase 3 — Resource enumeration & attack-surface map

- Load **`cloudfox`** — attacker-oriented AWS enumeration: endpoints, secrets
  in userdata/env, role-trusts, loot files, `permissions`/`principals` output.
  Start here on AWS.
- Load **`aws-enumeration`** — exhaustive per-service AWS CLI enumeration,
  all-regions discipline.
- Load **`azure-enumeration`** — ARM-plane enumeration across **all
  subscriptions** in the tenant (resources, VMs, apps, key vaults, networking).
- Load **`azure-entra-id`** — the Entra/AAD **directory** plane: users, groups,
  app registrations + service principals, role assignments, Conditional
  Access, dynamic-group abuse. The directory is a separate attack surface from
  ARM; enumerate both.
- Load **`gcp-enumeration`** — projects/folders/org hierarchy, per-project
  services, `testIamPermissions` brute-forcing when `get-iam-policy` is denied.

Iterate **all regions (AWS), all subscriptions (Azure), all projects + org
level (GCP)** — the thing you can escalate through is always in the region or
project nobody looks at. See `references/methodology.md` for the iteration
discipline.

## Phase 4 — IAM analysis & privilege escalation

- Load **`pmapper`** — builds the AWS IAM graph (`pmapper graph create`), then
  `pmapper query 'preds of policy admin'` / `argquery --preset privesc` to find
  who can reach admin and through which edge.
- Load **`pacu`** — AWS exploitation framework: enumeration modules plus
  **execution** of the escalation (`iam__privesc_scan` finds *and runs* the
  path — CreatePolicyVersion, AttachUserPolicy, PassRole+Lambda, etc.).
  pmapper tells you the path exists; pacu walks it.
- Load **`cloud-privilege-escalation`** — the cross-cloud technique catalog:
  AWS iam:*/PassRole families, Azure RBAC + Entra role abuse (Owner on
  subscription, App Admin → SP credential add), GCP
  `setIamPolicy`/`actAs`/SA-key-creation chains. Use it to translate a
  permission you *have* into an escalation you can *run* on any provider.

Every successful escalation yields a credential or a principal you now control
→ **go back to Phase 1 whoami with it.**

## Phase 5 — Loot: exposed storage

Load **`cloud-storage-exposure`** — S3 / Azure Blob / GCS: unauthenticated and
cross-account access tests, bucket/container policy review, listing and
exfil-grade download, name permutation discovery. Storage is the #1 source of
the *next* credential (config files, tfstate, backups, CI artifacts).

## Phase 6 — Loot: secrets

Load **`trufflehog`** — run it over everything you've pulled: repos, buckets,
container images, filesystem loot, CI logs; verified detectors tell you which
hits are live credentials. Also enumerate the **native secret stores** with the
provider enumeration skills: AWS Secrets Manager + SSM Parameter Store, Azure
Key Vault, GCP Secret Manager — read access to a secret store is usually game
over for whatever the secrets protect.

Every verified secret → **Phase 1 whoami.**

## Phase 7 — Metadata / SSRF pivot

Load **`metadata-ssrf-pivot`** — when you have SSRF, RCE, or a shell on cloud
compute: IMDSv1 vs IMDSv2 (token dance), Azure IMDS (`Metadata: true` header),
GCP metadata (`Metadata-Flavor: Google`), ECS task credentials endpoint.
Metadata credentials are the instance's role — they re-enter the loop at
Phase 1 and typically land you *inside* an account you previously only saw
from outside.

## Closing the loop & reporting

- Merge each sub-skill's `out/work-units.json` into one deduplicated top-level
  array for orchestration:

  ```
  python3 scripts/merge_work_units.py out/prowler/work-units.json \
      out/cloudfox/work-units.json out/pmapper/work-units.json \
      -o out/work-units.json
  ```

- rupu wiring — fan-out over the merged units, lead-agent dispatch to
  sub-skills by name, `assets.mark` asset model
  (account/subscription/project + principal + resource), and
  `findings.report` for verified issues: see `references/rupu.md`.
- Full phase-by-phase flow, mapping tables, iteration and credential-graph
  discipline: `references/methodology.md`.

Done means: a pass through phases 1–7 produced no new credential, no new
principal, no new account/subscription/project — and every verified finding is
reported with the chain that proved it.
