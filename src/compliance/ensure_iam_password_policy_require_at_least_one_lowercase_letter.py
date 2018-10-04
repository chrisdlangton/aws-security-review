import helpers


def ensure_iam_password_policy_require_at_least_one_lowercase_letter(account, rule_config):
  result = False
  iam = helpers.get_client('iam')
  data = iam.get_account_password_policy().get('PasswordPolicy')
  if data['RequireLowercaseCharacters'] == 'true':
    result = True

  return data, result


def report(record):
  print """
CIS version {version} Level {level} Recommendation {recommendation} ({scored})
Rule                  {rule}
Result                {result}
Rationale             {desc}
Recommended Control   {control}
""".format(
  rule=record['rule']['name'],
  result=record['last_result'],
  desc=record['rule']['purpose'],
  control=record['rule']['control'],
  version=record['rule']['version'],
  level=record['rule']['level'],
  recommendation=record['rule']['recommendation'],
  scored='Scored' if record['rule']['scored'] else 'Not Scored'
)

