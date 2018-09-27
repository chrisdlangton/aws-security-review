import boto3
import random
import string
import json
import sys
from os import path
from config import config
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


def date_converter(o):
  if isinstance(o, datetime):
    return o.__str__()


def result_object(*args, **kwargs):
  return json.dumps(kwargs, default=date_converter)