import helpers


control = ''

def password_policy_on(account, rule_config):
  global control
  result = False
  try:
    iam = helpers.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    for key, value in rule_config['settings'].items():
      if data[key] == value:
        result = True
      else:
        result = False
        control = " and password policy setting [%s] should be set to: %s." % (key, value)
        break
  except Exception as e:
    if type(e).__name__ == 'NoSuchEntityException':
      data = None
    else:
      print e
      return

  return data, result


def report(record):
  global control
  print """
Rule                  {rule}
Result                {result}
Description           {desc}
Recommended Control   {control}
""".format(
  rule=record['rule']['name'],
  result=record['last_result'],
  desc=record['rule']['purpose'],
  control=record['rule']['control'] + control
)

