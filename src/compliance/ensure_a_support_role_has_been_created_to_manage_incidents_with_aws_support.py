import helpers


def ensure_a_support_role_has_been_created_to_manage_incidents_with_aws_support(account, rule_config):
  result = False
  iam = helpers.get_client('iam')
  data = iam.list_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess', EntityFilter='Role')['PolicyRoles']
  for role in data:
    if role.get('RoleName'):
      result = True


  return data, result


def report(record):
  print """
Rule                  {rule}
Result                {result}
Rationale             {desc}
Recommended Control   {control}""".format(
      rule=record['rule']['name'],
      result=record['last_result'],
      desc=record['rule']['purpose'],
      control=record['rule']['control']
  )
