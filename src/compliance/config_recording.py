import helpers


def config_recording(account, rule_config):
  result = False

  aws_config = helpers.get_client('config')
  data = aws_config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
  for recorder in data:
    result = result or recorder['recording']

  return data, result


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
