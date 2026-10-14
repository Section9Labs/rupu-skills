-- Ingress security group rules open to the entire internet.
select
  group_id,
  security_group_rule_id,
  ip_protocol,
  from_port,
  to_port,
  coalesce(cidr_ipv4, cidr_ipv6) as source,
  region,
  account_id
from
  aws_vpc_security_group_rule
where
  not is_egress
  and (cidr_ipv4 = '0.0.0.0/0' or cidr_ipv6 = '::/0')
order by
  from_port nulls first;
