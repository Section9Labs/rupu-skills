-- GCP public Cloud SQL (0.0.0.0/0 authorized networks or public IP), and
-- service accounts with user-managed keys (long-lived stealable creds).
select
  i.name as resource,
  'cloudsql-open:' || i.database_version as detail,
  i.project
from
  gcp_sql_database_instance as i,
  jsonb_array_elements(i.ip_configuration -> 'authorizedNetworks') as net
where
  net ->> 'value' = '0.0.0.0/0'
union all
select
  k.service_account_name as resource,
  'user-managed-sa-key:' || k.name as detail,
  k.project
from
  gcp_service_account_key as k
where
  k.key_type = 'USER_MANAGED';
