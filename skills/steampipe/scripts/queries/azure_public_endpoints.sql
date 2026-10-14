-- Azure public database exposure: SQL server firewall rules open to the world,
-- plus VMs with public IPs.
select
  s.name as resource,
  'sqlserver-fw:' || (r -> 'properties' ->> 'startIpAddress') || '-'
    || (r -> 'properties' ->> 'endIpAddress') as detail,
  s.resource_group,
  s.subscription_id
from
  azure_sql_server as s,
  jsonb_array_elements(s.firewall_rules) as r
where
  (r -> 'properties' ->> 'startIpAddress') = '0.0.0.0'
union all
select
  vm.name as resource,
  'vm-public-ip:' || vm.public_ips::text as detail,
  vm.resource_group,
  vm.subscription_id
from
  azure_compute_virtual_machine as vm
where
  vm.public_ips is not null
  and jsonb_array_length(vm.public_ips) > 0;
