---
name: pmapper
description: Map AWS IAM into an attack graph with PMapper (Principal Mapper) and extract ranked privilege-escalation paths between principals; use after obtaining AWS credentials to find who can become admin, which chains of IAM edges get there, and to produce an executable worklist for Pacu.
license: Apache-2.0
metadata:
  author: Section9Labs
  domain: cloud
---

# PMapper — AWS IAM attack-graph analysis

PMapper (NCC Group's Principal Mapper, `principalmapper` on PyPI) pulls the entire
IAM configuration of an AWS account, builds a local directed graph of principals
(users/roles) connected by *edges* (actions that let one principal gain access to
another), and answers queries like "who can become admin, and how". It is the
**map** phase: it finds and ranks privesc chains but does not execute them.
Execution is handed to the `pacu` skill; exact exploit commands per method live
in the `cloud-privilege-escalation` skill.

Install: `pip install principalmapper` (CLI name: `pmapper`). Needs read access
to IAM (`iam:Get*`, `iam:List*` — SecurityAudit or ReadOnlyAccess works; it
degrades gracefully with less).

## 1. Build the graph

```
pmapper --profile target graph create
```

- `--profile target` — any AWS CLI profile / env-credential set. You can also
  rely on `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` env vars.
- Pulls users, roles, groups, managed+inline policies, instance profiles, and
  per-service config needed for edge detection (Lambda functions, EC2 instance
  profiles, CloudFormation stacks, CodeBuild projects, SageMaker, SSM, STS trust
  policies). Stores the graph under `~/.local/share/principalmapper/<account-id>/`
  (respects `$XDG_DATA_HOME`), so every later command is **offline** — no more
  API calls, no more CloudTrail noise after the initial pull.
- Multiple accounts: run `graph create` once per profile; select later with
  `--account 198765432100` instead of `--profile`.
- `pmapper graph list` — graphs on disk. `pmapper graph display` — summary
  (# users, # roles, # groups, # edges, admin count).

Organizations (map cross-account AssumeRole trust across an entire org):

```
pmapper --profile org-mgmt orgs create          # build org structure from the management account
pmapper orgs display --org o-exampleorgid       # show the account tree
pmapper --account 198765432100 graph create     # then graph each member account
```

With org data + per-account graphs, `analysis` and `query` resolve
cross-account `sts:AssumeRole` edges.

## 2. Ranked privesc analysis

```
pmapper --profile target analysis --output-type text
pmapper --profile target analysis --output-type json > out/pmapper-analysis.json
```

`analysis` runs every built-in risk check and prints findings: principals that
are admin without looking like it, non-admin principals with a path to admin,
MFA-less powerful users, risky trust policies. Each privesc finding embeds the
full edge chain. This is your ranked worklist.

## 3. Query the graph

```
pmapper query "preset privesc *"                              # all privesc paths, all principals
pmapper query "preset privesc user/dev-bob"                   # paths from one principal
pmapper query "who can do iam:PutUserPolicy with *"
pmapper query "who can do s3:GetObject with arn:aws:s3:::corp-data/*"
pmapper query "can user/dev-bob do iam:CreateAccessKey with arn:aws:iam::198765432100:user/admin-alice"
pmapper query "preset connected user/dev-bob *"               # every principal bob can reach
pmapper query "preset connected * role/prod-admin"            # everyone who can reach prod-admin
pmapper query -s "who can do kms:Decrypt with *"              # -s / --skip-admin: hide known admins
```

Grammar: `can <principal> do <action> [with <resource>] [when <cond>=<val>]`,
`who can do <action> [with <resource>]`, `preset privesc|connected|clusters|endgame ...`.
The non-interactive twin is `argquery`
(`pmapper argquery --principal '*' --action iam:PassRole --resource '*'`).
Full grammar, every preset, and the complete edge-type catalog:
**references/queries.md**.

Key semantics: `can ... do` answers **including indirect access** — if bob can
privesc to admin-alice, then "can bob do X" is *yes via admin-alice*. The
response names the intermediary; that intermediary chain is the attack path.

## 4. Visualize

```
pmapper --profile target visualize --filetype svg          # full IAM attack graph
pmapper visualize --filetype png --only-privesc            # only privesc edges/paths
```

Filetypes: `svg`, `png`, `dot`, `graphml` (dot/graphml feed Gephi/yEd for big
accounts). Requires graphviz for svg/png. The rendered graph is the fastest way
to spot hub roles (one role reachable from many users = highest-value target).

## 5. Read the output

A privesc result is a chain of edges:

```
user/dev-bob can escalate privileges by accessing the administrative principal role/prod-admin:
   user/dev-bob can create a Lambda function and pass role/lambda-deployer to it
   role/lambda-deployer can call sts:AssumeRole to access role/prod-admin
```

Read each line as `source -> (permission combo) -> destination`. The permission
combo in parentheses (e.g. `iam:PassRole + lambda:CreateFunction`) is the
*method*; the destination is the principal you become. Prioritize:

1. Shortest chains ending at an admin principal.
2. Chains whose first edge starts at the principal you currently control
   (`pmapper query "preset privesc user/<you>"`).
3. Edges that are quiet to execute (sts:AssumeRole, iam:CreateAccessKey) over
   noisy ones (new EC2 instances).

## 6. Parse into work units and hand off

```
python3 scripts/parse_pmapper.py --profile target -o out/work-units.json --assets out/assets.json
# or parse pre-captured output:
python3 scripts/parse_pmapper.py --input out/pmapper-analysis.json -o out/work-units.json
python3 scripts/parse_pmapper.py --input out/privesc.txt -o out/work-units.json
```

The script runs `pmapper query "preset privesc *"` (falling back between JSON
and text output) or parses a saved `analysis --output-type json` / query text
dump, and writes:

- `out/work-units.json` — a bare JSON array, one unit per privesc path:
  `{"id","title","targets":[source_arn, target_arn],"hints":{"edges":[...],"method":...,"account":...}}`
- `out/assets.json` — every principal seen (users, roles, admin flags).

Hand each unit to **pacu** (run `iam__privesc_scan` to confirm, then exploit the
method) and to **cloud-privilege-escalation** (exact CLI for the method named in
`hints.method`). Rupu fan-out wiring, `assets.mark`, and `findings.report`
usage: **references/rupu.md**. Umbrella skill: `cloud-security`; upstream
credential sources: `cloud-credential-enumeration`.

## Operational notes

- Re-run `graph create` after any successful escalation — new keys/roles change
  the graph (`pmapper graph create` overwrites the stored graph for the account).
- A principal marked `is_admin` by PMapper needs no path — you already won if
  you hold its credentials; verify with `aws sts get-caller-identity` and move
  to post-exploitation.
- PMapper evaluates policy conditions conservatively; a path it reports as
  conditional (MFA, SourceIp) may still be executable — test it with pacu rather
  than discarding it.
