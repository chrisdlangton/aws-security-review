import helpers


def ensure_hardware_mfa_is_enabled_for_the_root_account(account, rule_config):
  result = False

  iam = helpers.get_client('iam')
  summary = iam.get_account_summary()['SummaryMap']
  mfa_devices = iam.list_virtual_mfa_devices()['VirtualMFADevices']
  if 'AccountMFAEnabled' in summary and summary['AccountMFAEnabled'] == 1:
    for mfa_device in mfa_devices:
      if 'SerialNumber' in mfa_device:
        result = True

  return summary, result


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

