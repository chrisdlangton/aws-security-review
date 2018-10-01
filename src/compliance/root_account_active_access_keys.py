import helpers


FIELD_ACCESS_KEY_1_ACTIVE = 8
FIELD_ACCESS_KEY_2_ACTIVE = 13

def root_account_active_access_keys(account, rule_config):
  result = False

  iam = helpers.get_client('iam')
  response = iam.generate_credential_report()
  content = iam.get_credential_report()['Content']
  users = content.splitlines()
  # Look for the '<root_account>' user value and determine whether access keys are active.
  for user in users:
    if '<root_account>' in user:
      user_values = user.split(',')
      if user_values[FIELD_ACCESS_KEY_1_ACTIVE].lower() == 'false' and user_values[FIELD_ACCESS_KEY_2_ACTIVE].lower() == 'false':
        result = True

  return content, result


def report(record):
  print """
Rule                  {rule}
Result                {result}
Description           {desc}
Recommended Control   {control}
""".format(
  rule=record['rule']['name'],
  result=record['last_result'],
  desc=record['rule']['purpose'],
  control=record['rule']['control']
)
