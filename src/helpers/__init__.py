import boto3
import random
import string
import json
import sys
import pytz
import dateutil
from os import path
from config import config
import database as db
from datetime import datetime


credentials = None

def randomstr(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))


def configure_credentials(RoleName, Profile=None, Account='*', Region=None, RoleSessionName=randomstr(10)):
  global credentials
  session = boto3.Session(profile_name=Profile, region_name=Region)
  sts_client = session.client('sts')
  assumedRoleObject = sts_client.assume_role(
      RoleArn="arn:aws:iam::%s:role/%s" % (Account, RoleName),
      RoleSessionName=RoleSessionName
  )
  credentials = assumedRoleObject['Credentials']
  if Region:
    credentials['region'] = Region

  return credentials, sts_client


def get_credentials(RoleName, Profile=None, Region=None, Account='*', RoleSessionName=randomstr(10)):
  session = boto3.Session(profile_name=Profile, region_name=Region)
  sts_client = session.client('sts')
  return sts_client.assume_role(
      RoleArn="arn:aws:iam::%d:role/%s" % (Account, RoleName),
      RoleSessionName=RoleSessionName
  ), sts_client

def get_client(Service, Region=None, Profile=None, RoleName=None):
  global credentials
  if not credentials:
    credentials = get_credentials(RoleName, Profile, Region)
  elif not Region and credentials.get('region'):
    Region = credentials.get('region')

  return boto3.client(
      Service,
      aws_access_key_id=credentials['AccessKeyId'],
      aws_secret_access_key=credentials['SecretAccessKey'],
      aws_session_token=credentials['SessionToken'],
      region_name=Region
  )


def date_converter(o):
  if isinstance(o, datetime):
    return o.__str__()


def is_json(myjson):
  try:
    json_object = json.loads(myjson)
  except ValueError:
    return False
  except TypeError:
    return False
  del json_object
  return True


def evaluate_rule(data, result, account, rule_config, prefix=None):
  results = []
  now = datetime.utcnow().replace(tzinfo=pytz.UTC)
  record_key = "{prefix}{label}-{id}".format(
      label=rule_config['name'], id=account['id'], prefix=prefix or '')
  if rule_config.get('region'):
    record_key += "-%s" % rule_config['region']
  result_time = {
      'time': now,
      'compliance': result
  }
  result_obj = {
      'key': record_key,
      'alias': account['alias'],
      'account': account['id'],
      'rule': rule_config,
      'data': data,
      'last_result': 'COMPLIES' if result else 'NONCOMPLIANT',
      'results':  [result_time]
  }
  if db.exists(record_key):
    record = db.get(record_key)
    db.rem(record_key)
    record['last_result'] = result_obj['last_result']
    record['results'].append(result_time)
    db.set(record_key, record)
  else:
    db.set(record_key, result_obj)
  results.append(record_key)
  return results

UTC = pytz.timezone('UTC')
def to_iso8601(when=None, tz=UTC):
  if not when:
    when = datetime.now(tz)
  if not when.tzinfo:
    when = tz.localize(when)
  _when = when.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
  return _when[:-8] + _when[-5:] # remove microseconds

def from_iso8601(when=None, tz=UTC):
  _when = dateutil.parser.parse(when)
  if not _when.tzinfo:
    _when = tz.localize(_when)
  return _when