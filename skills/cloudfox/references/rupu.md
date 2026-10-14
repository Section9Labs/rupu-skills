# rupu wiring — cloudfox

This skill's parse step ends by writing `out/work-units.json` (a **bare JSON array**
— rupu's `for_each:` JSON-parses a file whose content starts with `[`) and
`out/assets.json`.

Import these shared reporting-pack skills BY NAME — do not re-invent them:

- **`work-units`** — canonical work-unit shape: `{"id","title","targets","hints"}`,
  targets = list of hosts/arns/urls/bucket names/principals, hints = tool context.
- **`coverage-assets`** — how to record discovered assets with rupu's `assets.mark`.
- **`finding-report`** — how to record verified issues with rupu's `findings.report`.

## Producing the units

```
python3 scripts/parse_cloudfox.py --dir ./cloudfox --out out/work-units.json --assets out/assets.json
```

Unit kinds emitted (see `hints.kind`): `endpoint`, `bucket`, `principal`
(cross-account / wildcard role trust, or instance-with-profile), `secret`
(SecretsManager/SSM name or suspicious env-var). Every unit carries
`hints.module`, `hints.account`, `hints.region` where known.

## Workflow fan-out

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: fan-out
    for_each: ${{ steps.load-units.output }}   # parses the bare array
    agent: cloud-operator
    prompt: |
      Work unit ${{ item.id }}: ${{ item.title }}
      Targets: ${{ item.targets }}
      Hints: ${{ item.hints }}
      Route by hints.kind:
        endpoint  -> web/API testing via cloud-security
        bucket    -> cloud-storage-exposure
        principal -> pmapper then pacu (assume-role / privesc)
        secret    -> pull value (loot/pull-secrets-commands.txt), then trufflehog
      Record assets per coverage-assets; report verified issues per finding-report.
```

## Lead-agent dispatch over the same units

```
units = json.load(open("out/work-units.json"))
for u in units:
    dispatch(agent="cloud-operator",
             task=f"{u['title']} — targets {u['targets']}",
             context=u["hints"])
```

## Asset model (`assets.mark` via coverage-assets)

Mark from `out/assets.json`:

- cloud account: `assets.mark(kind="cloud-account", id="123456789012", attrs={"provider":"aws","profile":"target"})`
- principal/role: `kind="principal"`, id = ARN, attrs = `{"trusts": "..."}`
- compute instance: `kind="compute-instance"`, id = instance ID, attrs = `{"public_ip","private_ip","instance_profile"}`
- storage bucket: `kind="storage-bucket"`, id = bucket name
- public endpoint: `kind="public-endpoint"`, id = URL, attrs = `{"service"}`
- secret: `kind="secret"`, id = secret/parameter name or `function:VAR`

## Findings (`findings.report` via finding-report)

Report only verified results, e.g.:

- cross-account role assumable without ExternalID (you ran `sts assume-role` and got creds)
  → severity high, evidence = AssumedRoleUser ARN from the response.
- env-var contained a live credential (validated by trufflehog) → severity high,
  evidence = redacted key ID + validation output.
- bucket publicly listable (confirmed by cloud-storage-exposure) → evidence = listing excerpt.

Include: title, severity, affected asset id (ARN/bucket/URL), evidence, and the
CloudFox module + loot file that produced the lead.

— vulture (silver-crown)
