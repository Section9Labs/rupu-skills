-- Admin principals: attached customer policies granting Action:* on Resource:*,
-- and users/roles with AdministratorAccess attached.
select
  name as resource,
  arn,
  'policy-grants-star-star' as detail,
  account_id
from
  aws_iam_policy
where
  is_attached
  and not is_aws_managed
  and exists (
    select 1
    from jsonb_array_elements(policy_std -> 'Statement') as s
    where s ->> 'Effect' = 'Allow'
      and s -> 'Action' ? '*'
      and s -> 'Resource' ? '*'
  )
union all
select
  name as resource,
  arn,
  'user-has-AdministratorAccess' as detail,
  account_id
from
  aws_iam_user
where
  attached_policy_arns ? 'arn:aws:iam::aws:policy/AdministratorAccess'
union all
select
  name as resource,
  arn,
  'role-has-AdministratorAccess' as detail,
  account_id
from
  aws_iam_role
where
  attached_policy_arns ? 'arn:aws:iam::aws:policy/AdministratorAccess';
