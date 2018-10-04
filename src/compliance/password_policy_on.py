import helpers


def password_policy_on(account, rule_config):
  result = False
  try:
    iam = helpers.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['AllowUsersToChangePassword'] == 'true':
      result = True
  except Exception as e:
    if type(e).__name__ == 'NoSuchEntityException':
      data = None
    else:
      raise e

  return data, result


def report(record):
  print """
Rule                  {rule}
Result                {result}
Rationale             {desc}
Recommended Control   {control}
""".format(
  rule=record['rule']['name'],
  result=record['last_result'],
  desc=record['rule']['purpose'],
  control=record['rule']['control']
)

