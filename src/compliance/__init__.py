import helpers
import json
import pytz
import database as db
from datetime import datetime
from yaml import load


rules = None
with open('rules.yaml', 'r') as f:
  rules = load(f)


def evaluate(data, result, account, rule_config, prefix=None):
  results = []
  now = datetime.utcnow().replace(tzinfo=pytz.UTC)
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
