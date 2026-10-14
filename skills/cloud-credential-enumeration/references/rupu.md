# rupu wiring — cloud-credential-enumeration

This skill plugs into rupu via the shared reporting pack. Import these skills BY
NAME rather than re-implementing their shapes:

- **work-units** — canonical work-unit splitter shape (`{"id","title","targets","hints"}`,
  bare JSON array in a file).
- **coverage-assets** — recording discovered assets with rupu's `assets.mark` tool.
- **finding-report** — recording verified issues with rupu's `findings.report` tool.

## Work-units files produced here

- `out/work-units.json` — from `scripts/classify_credentials.py`; one unit per
  credential found.
- `out/whoami-units.json` — from `scripts/whoami_all.py`; one unit per LIVE
  validated identity.

Both are bare JSON arrays (content starts with `[`) so rupu's `for_each:` can
JSON-parse them directly.

Unit shape (per the **work-units** skill):

```json
[
  {
    "id": "aws-akia-0001",
    "title": "AWS long-term key AKIAEXAMPLE000000000",
    "targets": ["AKIAEXAMPLE000000000"],
    "hints": {"provider": "aws", "type": "access_key_long_term",
              "source": "/loot/ci/.aws/credentials", "has_secret": "true"}
  },
  {
    "id": "azure-jwt-0002",
    "title": "Azure ARM bearer token for oid 00000000-0000-0000-0000-000000000001",
    "targets": ["00000000-0000-0000-0000-000000000001"],
    "hints": {"provider": "azure", "type": "jwt",
              "aud": "https://management.azure.com/",
              "tid": "00000000-0000-0000-0000-0000000000aa", "exp": "1735689600"}
  }
]
```

## Workflow fan-out

```yaml
- id: classify
  run: python3 skills/cloud-credential-enumeration/scripts/classify_credentials.py --input loot/ -o out/work-units.json --assets out/assets.json
- id: read_units
  tool: read_file
  path: out/work-units.json
- id: validate_each
  for_each: out/work-units.json      # JSON-parses the bare array
  do:
    prompt: >
      Using cloud-credential-enumeration, validate the credential in unit
      {{item.id}} (provider {{item.hints.provider}}, type {{item.hints.type}}),
      establish its identity, map its roles/assignable principals, and route to
      the correct sibling skill. Record assets and findings. Any NEW credential
      you obtain: write it to loot/ and emit a new work unit.
```

Lead-agent dispatch over the same array:

```yaml
- id: dispatch_creds
  dispatch:
    units_file: out/work-units.json
    agent_prompt: >
      You own one credential work unit: {{unit.title}}. Follow the
      cloud-credential-enumeration skill: validate, whoami, map, route by name
      (pmapper/pacu/cloud-privilege-escalation, azure-entra-id,
      cloudfox/*-enumeration, prowler/scoutsuite, cloud-storage-exposure).
```

## Assets (coverage-assets → `assets.mark`)

Mark every identity and container of identities:

- cloud accounts / subscriptions / tenants / projects:
  `assets.mark type=cloud-account id=aws:123456789012`,
  `azure-subscription:00000000-...`, `gcp-project:example-prod-123456`
- principals: `assets.mark type=principal id=arn:aws:iam::123456789012:user/ci-deploy`
  (hints: provider, kind=user|role|sp|sa, source credential unit id)
- secrets/credentials themselves: `assets.mark type=secret id=AKIAEXAMPLE000000000`
  (hints: live=true|false, expiry)
- roles reachable via assume/impersonation: `type=principal` with
  `hints.reachable_from=<unit id>`

`scripts/whoami_all.py --assets out/identities.json` emits the asset records as
JSON; feed each entry to `assets.mark`.

## Findings (finding-report → `findings.report`)

Report only VERIFIED items:

- live leaked credential (validated with whoami) — severity by privilege level;
- wildcard / cross-account trust policy you confirmed assumable;
- SA impersonation chain confirmed with `print-access-token`;
- refresh tokens / cleartext SP secrets recovered from CLI caches.

Include in each report: the whoami output, the permission evidence
(policy JSON / enumerate-iam / testIamPermissions results), and the work-unit id
that led there.

## Chain-back

Umbrella: **cloud-security**. Every credential produced by ANY sibling skill
(pacu loot, Key Vault secrets, bucket contents via **cloud-storage-exposure** +
**trufflehog**, metadata tokens from **cloud-privilege-escalation**) must be
written back into a loot dir and re-run through `classify_credentials.py` so it
re-enters this hub as a new work unit.
