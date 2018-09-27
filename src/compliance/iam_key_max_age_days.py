import helpers
import json
import pytz
import database as db
from config import config
from datetime import datetime

def evaluate(account, rule_config, prefix=None):
  results = []
  now = datetime.utcnow().replace(tzinfo=pytz.UTC)

  iam = helpers.get_client('iam')
  for user in iam.list_users().get('Users'):
    for data in iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata'):
      result = False
      rule_value = rule_config['threshold']      
      create_date = data['CreateDate']
      delta = now - create_date

      if delta.days <= rule_value and data['Status'] == 'Active':
        result = True

      record_key = "{prefix}{label}-{id}".format(label=rule_config['name'] , id=data['AccessKeyId'], prefix=prefix or '')

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

