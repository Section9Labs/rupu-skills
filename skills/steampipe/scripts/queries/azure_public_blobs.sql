-- Azure anonymous blob containers and storage accounts permitting public blob access.
select
  c.name as resource,
  c.account_name,
  c.public_access as detail,
  c.resource_group,
  c.subscription_id
from
  azure_storage_container as c
where
  c.public_access is not null
  and c.public_access <> 'None'
union all
select
  a.name as resource,
  a.name as account_name,
  'account-allows-blob-public-access' as detail,
  a.resource_group,
  a.subscription_id
from
  azure_storage_account as a
where
  a.allow_blob_public_access;
