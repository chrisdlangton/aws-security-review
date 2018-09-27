import database as db
from config import config
from yaml import load, dump
import scripts
import boto3
import pytz
from datetime import datetime


from pprint import pprint

now = datetime.utcnow().replace(tzinfo=pytz.UTC)
print "Started at %s" % now
# ok, nok = scripts.get_loggers()

db.deldb()

for account in config['accounts']:
  id = account['id']
  if not db.exists(id):
    db.set(id, account['alias'])

  role = None
  profile = None
  if account['assumeRole']:
    role = account['assumeRole']
  if account['profile']:
    profile = account['profile']
  scripts.configure_credentials(role, profile, id)

  iam = scripts.get_client('iam')
  for user in iam.list_users().get('Users'):
    for keyData in iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata'):
      scripts.iam_key_max_age_days(account, keyData)
  # s3 = get_client('s3')
  # pprint(s3.list_buckets())

  for region in account['regions']:
    print "region: %s" % region

pprint(db.get('iam-key-max-age-days-AKIAI3XZ7DMWCB2XWA7A'))
db.dump()
# ok.close
# nok.close
