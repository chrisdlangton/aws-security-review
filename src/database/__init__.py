import os
import json
import pickledb
from config import config

# https://patx.github.io/pickledb/commands.html
database = pickledb.load(os.path.join(
    config['pickledb']['base_dir'],
    config['pickledb']['filename']), True)

def exists(key):
  return database.exists(str(key))


def get(key):
  return json.loads(database.get(str(key)))


def rem(key):
  return database.rem(str(key))


def deldb():
  return database.deldb()


def getall():
  return database.getall()


def set(key, value):
  return database.set(str(key), value)

def append(key, more):
  return database.append(str(key), more)


def dump():
  return database.dump()
