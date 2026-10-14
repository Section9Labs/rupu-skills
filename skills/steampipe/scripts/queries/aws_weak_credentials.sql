-- Weak credential posture: console users without MFA, and active access keys
-- older than 90 days (long-lived creds worth stealing / likely sprayed around).
select
  name as resource,
  'console-user-no-mfa' as detail,
  null as access_key_id,
  null as create_date,
  account_id
from
  aws_iam_user
where
  login_profile is not null
  and not mfa_enabled
union all
select
  user_name as resource,
  'stale-active-access-key' as detail,
  access_key_id,
  create_date::text as create_date,
  account_id
from
  aws_iam_access_key
where
  status = 'Active'
  and create_date < now() - interval '90 days';
