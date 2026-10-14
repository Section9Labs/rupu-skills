# PMapper query language, presets, and edge types

## Query grammar (`pmapper query "<string>"`)

```
can <principal> do <action> [with <resource>] [when <condition_key>=<value> ...]
who can do <action> [with <resource>] [when <condition_key>=<value> ...]
preset <preset_name> <args...>
```

- `<principal>`: `user/<name>`, `role/<name>`, or a full ARN
  (`arn:aws:iam::198765432100:user/dev-bob`). `*` matches all principals in
  `preset` queries.
- `<action>`: a single `service:Action` (no wildcards in queries; use argquery
  loops for sweeps).
- `<resource>`: full ARN, may contain `*` (`arn:aws:s3:::corp-data/*`).
  Defaults to `*`.
- `when` clauses set condition-context values for policy evaluation:
  `... when aws:MultiFactorAuthPresent=true`.

Global flags that matter for queries:

| flag | effect |
|---|---|
| `--profile <p>` / `--account <id>` | select which stored graph to query |
| `-s` / `--skip-admin` | suppress results for principals already identified as admins |
| `-u` / `--include-unauthorized` (argquery) | also list principals that were denied, with the deny reason |

### Examples

```
pmapper query "who can do iam:PutUserPolicy with *"
pmapper query "who can do iam:PassRole with arn:aws:iam::198765432100:role/prod-admin"
pmapper query "can user/dev-bob do s3:GetObject with arn:aws:s3:::corp-data/export.sql"
pmapper query "can role/ci-runner do sts:AssumeRole with arn:aws:iam::198765432100:role/prod-admin"
pmapper query "who can do secretsmanager:GetSecretValue with * when aws:MultiFactorAuthPresent=false"
```

Answers to `can ... do` include **transitive** access: `user/dev-bob can do X
through role/prod-admin` means bob first escalates to prod-admin (the privesc
chain is printed), then performs X. That printed chain is the attack path.

## argquery — the scriptable form

```
pmapper argquery --principal '*' --action iam:PutUserPolicy --resource '*'
pmapper argquery --principal user/dev-bob --action s3:GetObject \
    --resource 'arn:aws:s3:::corp-data/*' --condition aws:MultiFactorAuthPresent=false
pmapper argquery --principal '*' --preset privesc
pmapper argquery -s --principal '*' --preset connected --resource '*'
```

`--condition key=value` is repeatable. argquery is what you call from shell
loops when sweeping many actions:

```
for a in iam:CreateAccessKey iam:PutUserPolicy iam:AttachUserPolicy lambda:UpdateFunctionCode; do
  pmapper argquery -s --principal '*' --action "$a" --resource '*'
done
```

## Presets

| preset | invocation | what it answers |
|---|---|---|
| `privesc` | `pmapper query "preset privesc *"` / `"preset privesc user/dev-bob"` | all privilege-escalation paths (chains of edges ending at an admin). The core offensive query. |
| `connected` | `"preset connected user/dev-bob *"`, `"preset connected * role/prod-admin"` | which principals can reach which other principals via any edge chain (not only to admins). Use `* <target>` to enumerate everyone who can reach a specific role. |
| `clusters` | `"preset clusters user/dev-bob"` | groups principals by shared tag/access cluster — useful for spotting peer accounts likely to have the same holes. |
| `endgame` | `"preset endgame arn:aws:s3:::corp-data/*"` with an action context e.g. `pmapper argquery --preset endgame --action s3:GetObject --resource 'arn:aws:s3:::corp-data/*'` | every principal that can ultimately access a given resource, directly or via escalation. Resource-first targeting: start from the crown-jewel bucket/KMS key and work backwards. |

`preset privesc *` output format (text):

```
user/dev-bob can escalate privileges by accessing the administrative principal role/prod-admin:
   user/dev-bob can create a Lambda function and pass role/lambda-deployer to it
   role/lambda-deployer can call sts:AssumeRole to access role/prod-admin
user/intern-carol cannot escalate privileges.
```

One block per source principal; indented lines are the edge chain in order.

## Edge types PMapper detects

Each edge means "source can obtain the credentials/execution context of
destination". Current edge checkers:

| service | edge | permissions behind it |
|---|---|---|
| STS | assume role | `sts:AssumeRole` + role trust policy allows source |
| IAM | self/other-user key creation | `iam:CreateAccessKey` on the user |
| IAM | console takeover | `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` |
| IAM | policy manipulation (treated as admin-making) | `iam:PutUserPolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:UpdateAssumeRolePolicy`, `iam:AddUserToGroup`, ... |
| EC2 | run instance with instance profile | `iam:PassRole` + `ec2:RunInstances` (destination = role in the instance profile) |
| Lambda | create function with role | `iam:PassRole` + `lambda:CreateFunction` (+ `lambda:InvokeFunction` or an event source) |
| Lambda | modify existing function | `lambda:UpdateFunctionCode` / `lambda:UpdateFunctionConfiguration` on a function with a role |
| CloudFormation | create/update stack with role | `iam:PassRole` + `cloudformation:CreateStack`/`UpdateStack` |
| CodeBuild | create/start project with service role | `iam:PassRole` + `codebuild:CreateProject`/`StartBuild`/`StartBuildBatch` |
| SageMaker | create notebook/training job with role | `iam:PassRole` + `sagemaker:CreateNotebookInstance` / `CreateTrainingJob` / `CreatePresignedNotebookInstanceUrl` |
| SSM | command/session on instance | `ssm:SendCommand` / `ssm:StartSession` targeting an instance whose profile role is the destination |
| AutoScaling | launch config/template with profile | `iam:PassRole` + `autoscaling:CreateAutoScalingGroup`/`CreateLaunchConfiguration` |

Exploitation commands for every one of these methods: see the
`cloud-privilege-escalation` skill (`references/aws.md`), and confirm/execute
with `pacu` (`iam__privesc_scan`).

## Graph storage & maintenance

- Location: `~/.local/share/principalmapper/<account-id>/` (`graph.json` + per-node data). Override root with `$XDG_DATA_HOME`.
- `pmapper graph list` / `pmapper graph display` — inventory and stats.
- Rebuild after any IAM change you cause: `pmapper --profile target graph create` (overwrites).
- Copy the directory between machines to analyze offline — no credentials needed once the graph exists.
