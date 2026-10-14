-- GCP ingress firewall rules open to 0.0.0.0/0, plus instances with external IPs.
select
  f.name as resource,
  'firewall:' || f.allowed::text as detail,
  f.project,
  null as external_ip
from
  gcp_compute_firewall as f
where
  f.direction = 'INGRESS'
  and not f.disabled
  and f.source_ranges ? '0.0.0.0/0'
union all
select
  i.name as resource,
  'instance-external-ip' as detail,
  i.project,
  nic -> 'accessConfigs' -> 0 ->> 'natIP' as external_ip
from
  gcp_compute_instance as i,
  jsonb_array_elements(i.network_interfaces) as nic
where
  nic -> 'accessConfigs' -> 0 ->> 'natIP' is not null;
