-- Azure NSG inbound rules allowing traffic from the internet.
select
  sg.name as resource,
  r ->> 'name' as rule_name,
  r -> 'properties' ->> 'destinationPortRange' as ports,
  r -> 'properties' ->> 'sourceAddressPrefix' as source,
  r -> 'properties' ->> 'protocol' as protocol,
  sg.resource_group,
  sg.subscription_id
from
  azure_network_security_group as sg,
  jsonb_array_elements(sg.security_rules) as r
where
  r -> 'properties' ->> 'access' = 'Allow'
  and r -> 'properties' ->> 'direction' = 'Inbound'
  and (
    r -> 'properties' ->> 'sourceAddressPrefix' in ('*', '0.0.0.0/0', 'Internet', 'any')
    or r -> 'properties' -> 'sourceAddressPrefixes' ? '0.0.0.0/0'
  );
