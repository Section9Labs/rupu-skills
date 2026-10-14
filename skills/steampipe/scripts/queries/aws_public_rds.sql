-- Publicly accessible RDS instances and public RDS snapshots.
select
  db_instance_identifier as resource,
  endpoint_address as endpoint,
  engine as detail,
  region,
  account_id
from
  aws_rds_db_instance
where
  publicly_accessible
union all
select
  db_snapshot_identifier as resource,
  null as endpoint,
  'public-snapshot:' || engine as detail,
  region,
  account_id
from
  aws_rds_db_snapshot,
  jsonb_array_elements(db_snapshot_attributes) as attr
where
  attr ->> 'AttributeName' = 'restore'
  and attr -> 'AttributeValues' ? 'all';
