# -*- coding: utf-8 -*-
"""Vendor Patching.

This is only required due to type issues in the library, seems the
maintainer runs macos as I am seeing linux is expecting a bit stronger
type handling
"""
import os, json, pickledb
from helpers import *

# https://patx.github.io/pickledb/commands.html
c = get_config()
database = pickledb.load(os.path.join(
    c['pickledb']['base_dir'],
    c['pickledb']['filename']), True)


def exists(key) -> bool:
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
