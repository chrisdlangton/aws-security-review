from datetime import datetime
from config import config
from compliance import rules
from yaml import load, dump
import helpers
import boto3
import pytz
import importlib
import database as db

now = datetime.utcnow().replace(tzinfo=pytz.UTC)
# db.deldb()


def check_rule(rule):
  rule_name = "compliance.%s" % rule['name']
  rule_obj = importlib.import_module(rule_name)
  rule_fn = getattr(rule_obj, rule['name'])
  try:
    data, result = rule_fn(account, rule)
  except Exception as e:
    print e
    return False

  results = helpers.evaluate_rule(data, result, account, rule)
  if results:
    report = getattr(rule_obj, 'report')
    for result in results:
      record = db.get(result)
      if record['last_result'] == 'NONCOMPLIANT':
        report(record)
        break

rules = [x for x in rules if x.get('level') == 2]

for account in config['accounts']:
  print "Started at %s" % now
  id = account['id']
  print 'Scanning %d' % id

  role = None
  profile = None
  if account.get('assumeRole'):
    role = account['assumeRole']
  if account.get('profile'):
    profile = account['profile']

  helpers.configure_credentials(role, profile, id)

  for rule in rules:
    if not rule.get('regions'):
      check_rule(rule)

  for rule in rules:
    if rule.get('regions'):
      for region in rule.get('regions'):
        helpers.configure_credentials(role, profile, id, region)
        rule['region'] = region
        check_rule(rule)

db.dump()
