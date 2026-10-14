-- Public and shareable EBS snapshots (restorable cross-account for offline looting).
select
  snapshot_id as resource,
  volume_id,
  volume_size,
  encrypted,
  region,
  account_id,
  create_volume_permissions
from
  aws_ebs_snapshot
where
  create_volume_permissions @> '[{"Group":"all"}]'
  or jsonb_array_length(coalesce(create_volume_permissions, '[]'::jsonb)) > 0;
