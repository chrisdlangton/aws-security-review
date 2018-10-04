import helpers
import time
import pytz
from datetime import datetime


def ensure_credentials_unused_for_90_days_or_greater_are_disabled(account, rule_config):
  result = False

  now = datetime.utcnow().replace(tzinfo=pytz.UTC)
  iam = helpers.get_client('iam')
  response = iam.generate_credential_report()['State']
  if response == 'COMPLETE':
    content = iam.get_credential_report()['Content']
    users = content.splitlines()
    cols = users.pop(0).split(',')

    output = list()
    for s in users:
      report = {cols[k]:item for k, item in enumerate(s.split(","))}
      if report['user'] == '<root_account>':
        continue

      if (report['password_enabled'] == 'false' and
         report['access_key_1_active'] == 'false' and
         report['access_key_2_active'] == 'false' and
         report['cert_1_active'] == 'false' and
         report['cert_2_active'] == 'false'):
        continue

      user_creation_time = helpers.from_iso8601(report['user_creation_time'])
      delta = now - user_creation_time
      if delta.days < 90:
        continue
      
      if report['password_enabled'] == 'true':
        password_last_changed = helpers.from_iso8601(report['password_last_changed'])
        delta = now - password_last_changed
        if delta.days >= 90:
          output.append('password_last_changed %d days ago' % delta.days)
          break

      if report['access_key_1_active'] == 'true':
        access_key_1_last_rotated = helpers.from_iso8601(report['access_key_1_last_rotated'])
        delta = now - access_key_1_last_rotated
        if delta.days >= 90:
          output.append('access_key_1_last_rotated %d days ago' % delta.days)
          break

      if report['access_key_2_active'] == 'true':
        access_key_2_last_rotated = helpers.from_iso8601(report['access_key_2_last_rotated'])
        delta = now - access_key_2_last_rotated
        if delta.days >= 90:
          output.append('access_key_2_last_rotated %d days ago' % delta.days)
          break

      if report['cert_1_active'] == 'true':
        cert_1_last_rotated = helpers.from_iso8601(report['cert_1_last_rotated'])
        delta = now - cert_1_last_rotated
        if delta.days >= 90:
          output.append('cert_1_active %d days ago' % delta.days)
          break

      if report['cert_2_active'] == 'true':
        cert_2_last_rotated = helpers.from_iso8601(report['cert_2_last_rotated'])
        delta = now - cert_2_last_rotated
        if delta.days >= 90:
          output.append('cert_2_active %d days ago' % delta.days)
          break

      result = True
      break
    print '\n'.join(output)

    return content, result
  else:
    time.sleep(3)
    return ensure_credentials_unused_for_90_days_or_greater_are_disabled(account, rule_config)



def report(record):
  print """
CIS version {version} Level {level} Recommendation {recommendation} ({scored})
Rule                  {rule}
Result                {result}
Description           {desc}
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

