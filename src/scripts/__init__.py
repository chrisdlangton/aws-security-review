import json
import boto3
from config import config
import random
import string
import logging
import sys
from os import path
import pytz
from datetime import datetime
import database as db

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

  return boto3.client(
      Service,
      aws_access_key_id=credentials['AccessKeyId'],
      aws_secret_access_key=credentials['SecretAccessKey'],
      aws_session_token=credentials['SessionToken'],
      region_name=Region
  )

def get_loggers():
  compliant = open(
    path.join(
      config['outputs']['compliant']['base_dir'],
      config['outputs']['compliant']['filename']
    ), 'a'
  )
  noncompliant = open(
    path.join(
      config['outputs']['compliant']['base_dir'],
      config['outputs']['compliant']['filename']
    ), 'a'
  )
  return compliant, noncompliant


def iam_key_max_age_days(account, data, label='iam-key-max-age-days'):
  now = datetime.utcnow().replace(tzinfo=pytz.UTC)
  rule_value = config['compliance'][label]
  
  create_date = data['CreateDate']
  create_date.replace(tzinfo=None)
  delta = now - create_date

  result = True
  if delta.days > rule_value and data['Status'] == 'Active':
    result = False

  pk = "{label}-{id}".format(label=label, id=data['AccessKeyId'])
  result_time = {
    'time': now,
    'compliance': result
  }
  result_obj = json.dumps({
    'pk': pk,
    'alias': account['alias'],
    'account': account['id'],
    'rule': label,
    'threshold': rule_value,
    'identifier': data['AccessKeyId'],
    'value': delta.days,
    'results': [result_time]
  }, default=date_converter)
  if db.exists(pk):
    record = json.loads(db.get(pk))
    db.rem(pk)
    record['results'].append(result_time)
    db.set(pk, json.dumps(record, default=date_converter))
  else:
    db.set(pk, result_obj)

  return result, result_obj


def date_converter(o):
  if isinstance(o, datetime):
    return o.__str__()
