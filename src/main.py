import helpers
import boto3
import pytz
import importlib
import database as db
from datetime import datetime
from config import config
from compliance import rules, evaluate
from yaml import load, dump


now = datetime.utcnow().replace(tzinfo=pytz.UTC)

db.deldb()

for account in config['accounts']:
  print "Started at %s" % now
  id = account['id']
  print 'Scanning %d' % id

  role = None
  profile = None
  if account['assumeRole']:
    role = account['assumeRole']
  if account['profile']:
    profile = account['profile']
  helpers.configure_credentials(role, profile, id)

  for rule in rules:
    rule_name = "compliance.%s" % rule['name']
    rule_obj = importlib.import_module(rule_name)
    rule_fn = getattr(rule_obj, rule['name'])
    data, result = rule_fn(account, rule)
    results = evaluate(data, result, account, rule)
    if results:
      report = getattr(rule_obj, 'report')
      for result in results:
        record = db.get(result)
        if record['last_result'] == 'NONCOMPLIANT':
          report(record)
          break

  # for region in account['regions']:
  #   print "region: %s" % region

db.dump()