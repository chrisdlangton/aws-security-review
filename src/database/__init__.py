import os
import json
import pickledb
from config import config
import helpers

# https://patx.github.io/pickledb/commands.html
database = pickledb.load(os.path.join(
    config['pickledb']['base_dir'],
    config['pickledb']['filename']), True)

def exists(key):
  return database.exists(str(key))


def get(key):
  record = database.get(str(key))
  if helpers.is_json(record):
    return json.loads(record)
  else:
    return record


def rem(key):
  return database.rem(str(key))


def deldb():
  return database.deldb()


def getall():
  return database.getall()


def set(key, value):
  if not isinstance(value, basestring):
    return database.set(str(key), json.dumps(value, default=helpers.date_converter))
  else:
    return database.set(str(key), value)

def append(key, more):
  return database.append(str(key), more)


def dump():
  return database.dump()
