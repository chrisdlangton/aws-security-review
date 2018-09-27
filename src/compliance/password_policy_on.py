import helpers
import json
import pytz
import database as db
from config import config
from datetime import datetime


def evaluate(account, rule_config, prefix=None):
  result = False
  results = []
  now = datetime.utcnow().replace(tzinfo=pytz.UTC)

  iam = helpers.get_client('iam')
  try:
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['AllowUsersToChangePassword']:
      result = True
  except Exception as e:
    if type(e).__name__ == 'NoSuchEntityException':
      data = None
    else:
      print e
      return

  record_key = "{prefix}{label}-{id}".format(label=rule_config['name'] , id=account['id'], prefix=prefix or '')

  result_time = {
    'time': now,
    'compliance': result
  }
  result_obj = helpers.result_object(
    key=record_key,
    alias=account['alias'],
    account=account['id'],
    rule=rule_config,
    data=data,
    last_result='COMPLIES' if result else 'NONCOMPLIANT',
    results=[result_time])

  if db.exists(record_key):
    record = json.loads(db.get(record_key))
    db.rem(record_key)
    record['last_result'] = result_obj.last_result
    record['results'].append(result_time)
    db.set(record_key, json.dumps(record, default=helpers.date_converter))
  else:
    db.set(record_key, result_obj)

  results.append(record_key)


  return results


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

