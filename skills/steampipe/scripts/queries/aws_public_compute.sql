-- Internet-facing compute: EC2 with public IPs and internet-facing load balancers.
select
  instance_id as resource,
  public_ip_address as endpoint,
  instance_type as detail,
  region,
  account_id
from
  aws_ec2_instance
where
  public_ip_address is not null
union all
select
  name as resource,
  dns_name as endpoint,
  'alb:' || scheme as detail,
  region,
  account_id
from
  aws_ec2_application_load_balancer
where
  scheme = 'internet-facing'
union all
select
  name as resource,
  dns_name as endpoint,
  'nlb:' || scheme as detail,
  region,
  account_id
from
  aws_ec2_network_load_balancer
where
  scheme = 'internet-facing';
