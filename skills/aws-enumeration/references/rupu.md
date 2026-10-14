# rupu wiring — aws-enumeration

The scripted sweep ends by writing `out/work-units.json` (a **bare JSON array** —
rupu's `for_each:` JSON-parses a file whose content starts with `[`) and
`out/assets.json`:

```
python3 scripts/aws_enum.py --profile target --regions all --outdir out/awsenum
python3 scripts/aws_to_work_units.py --inventory out/awsenum/inventory.json \
    --out out/work-units.json --assets out/assets.json
```

Import these shared reporting-pack skills BY NAME — do not re-invent them:

- **`work-units`** — the canonical work-unit shape: `{"id","title","targets","hints"}`
  with targets = hosts/arns/urls/bucket names/principals.
- **`coverage-assets`** — recording assets with rupu's `assets.mark` tool.
- **`finding-report`** — recording verified issues with rupu's `findings.report` tool.

Unit kinds emitted (`hints.kind`): `public-resource` (instance public IP,
internet-facing LB, API/CloudFront endpoint, public RDS, 0.0.0.0/0 security group),
`principal` (cross-account/wildcard role trust, instance profile), `secret`
(SecretsManager secret, SSM parameter, Lambda env var), `logging-gap`
(no CloudTrail trail in any swept region). Each carries `hints.service`,
`hints.account`, `hints.region`.

## Workflow fan-out

```yaml
steps:
  - id: load-units
    tool: read_file
    args: { path: out/work-units.json }
  - id: fan-out
    for_each: ${{ steps.load-units.output }}   # bare array parses directly
    agent: cloud-operator
    prompt: |
      Work unit ${{ item.id }}: ${{ item.title }}
      Targets: ${{ item.targets }}
      Hints: ${{ item.hints }}
      Route by hints.kind:
        public-resource -> probe the endpoint/IP (web, service, DB) via cloud-security
        principal       -> pmapper graph query, then pacu / sts assume-role
        secret          -> pull the value (service-sweep.md commands), then trufflehog
        logging-gap     -> report via finding-report; proceed with low-detection ops
      Mark assets per coverage-assets; report verified issues per finding-report.
```

## Lead-agent dispatch

```
units = json.load(open("out/work-units.json"))
for u in units:
    dispatch(agent="cloud-operator",
             task=f"{u['title']} — targets {u['targets']}",
             context=u["hints"])
```

## Asset model (`assets.mark` via coverage-assets)

From `out/assets.json`:

- cloud account: `assets.mark(kind="cloud-account", id="123456789012", attrs={"provider":"aws","arn":"<caller arn>"})`
- principal: `kind="principal"`, id = user/role ARN, attrs = `{"trusts","source"}`
- compute instance: `kind="compute-instance"`, id = instance ID,
  attrs = `{"public_ip","private_ip","instance_profile","region"}`
- storage bucket: `kind="storage-bucket"`, id = bucket name
- public endpoint: `kind="public-endpoint"`, id = URL/DNS name, attrs = `{"service","region"}`
- secret: `kind="secret"`, id = secret/parameter name or `function:VAR`

## Findings (`findings.report` via finding-report)

Verified examples:

- role assumed cross-account without ExternalID → high; evidence = `sts assume-role`
  response ARN.
- public snapshot/AMI confirmed (`createVolumePermission` group `all`) → high;
  evidence = the attribute JSON.
- SSM parameter contained live DB creds (validated connection) → high.
- CloudTrail disabled in all regions → medium; evidence = empty `describe-trails`
  across the swept region list.
- security group open to 0.0.0.0/0 on an admin port with a live listener → severity
  per exposure; evidence = SG JSON + probe result.

Include title, severity, asset id (ARN/name/URL), evidence, and the exact CLI call
that produced it.

— vulture (silver-crown)
