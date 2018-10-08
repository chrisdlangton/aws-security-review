import helpers


def ensure_iam_policies_that_allow_full_administrative_privileges_are_not_created(account, rule_config):
  result = False
  data = list()
  iam = helpers.get_client('iam')
  policies = iam.list_policies(Scope='Local')['Policies']
  for p in policies:
    policy = iam.get_policy(PolicyArn=p['Arn'])['Policy']
    version = policy['DefaultVersionId']
    statements = iam.get_policy_version(PolicyArn=p['Arn'], VersionId=version)['PolicyVersion']['Document']['Statement']
    policy['Statement'] = statements
    for statement in statements:
      if statement['Effect'] == 'Allow':
        actions = list()
        if isinstance(statement['Action'], list):
          actions = statement['Action']
        else:
          actions.append(statement['Action'])

        stared = False
        for action in actions:
          if action == '*' or ':*' in action:
            stared = True

        if stared:
          resources = list()
          if isinstance(statement['Resource'], list):
            resources = statement['Resource']
          else:
            resources.append(statement['Resource'])
          
          for resource in resources:
            if resource == '*':
              data.append(policy)
              break

  if not data:
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
