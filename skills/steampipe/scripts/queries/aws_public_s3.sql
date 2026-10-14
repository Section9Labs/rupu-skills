-- Public S3 buckets: public policy, public ACL grants, or Block Public Access disabled.
select
  name,
  arn,
  region,
  account_id,
  bucket_policy_is_public,
  block_public_acls,
  block_public_policy,
  restrict_public_buckets
from
  aws_s3_bucket
where
  bucket_policy_is_public
  or not block_public_acls
  or not block_public_policy
  or not restrict_public_buckets;
