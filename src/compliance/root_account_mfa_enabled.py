import helpers


def root_account_mfa_enabled(account, rule_config):
  result = False

  iam = helpers.get_client('iam')
  summary = iam.get_account_summary()['SummaryMap']
  mfa_devices = iam.list_virtual_mfa_devices()['VirtualMFADevices']
  if 'AccountMFAEnabled' in summary and summary['AccountMFAEnabled'] == 1:
    if rule_config.get('hardwareMFA') and rule_config['hardwareMFA']:
      for mfa_device in mfa_devices:
          if 'SerialNumber' in mfa_device:
            result = True
    else:
      result = True

  return summary, result


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
