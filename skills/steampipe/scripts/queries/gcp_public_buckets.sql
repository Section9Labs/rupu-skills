-- GCS buckets granting access to allUsers / allAuthenticatedUsers.
select
  b.name as resource,
  b.location,
  b.project,
  binding ->> 'role' as role,
  binding -> 'members' as members
from
  gcp_storage_bucket as b,
  jsonb_array_elements(b.iam_policy -> 'bindings') as binding
where
  binding -> 'members' ?| array['allUsers', 'allAuthenticatedUsers'];
