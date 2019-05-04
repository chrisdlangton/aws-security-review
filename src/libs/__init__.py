import os
import boto3
import random
import string
import json
import sys
import pytz
import dateutil
import logging
import colorlog
import pickledb
import importlib
import yaml
from os import path, getcwd
from datetime import datetime
from xxhash import xxh32_hexdigest
from typing import Tuple

credentials = None
config = {}


class Database:
    database = None

    def __init__(self):
        # https://patx.github.io/pickledb/commands.html
        c = get_config('config')
        self.database = pickledb.load(os.path.join(
            c['pickledb']['base_dir'],
            c['pickledb']['filename']), True)

    def exists(self, key) -> bool:
        return self.database.exists(str(key))

    def get(self, key):
        record = self.database.get(str(key))
        if is_json(record):
            return json.loads(record)
        else:
            return record

    def rem(self, key):
        return self.database.rem(str(key))

    def deldb(self):
        return self.database.deldb()

    def getall(self):
        records = []
        for key in self.database.getall():
            record = self.get(key)
            if record:
                records.append(record)
        return records

    def set(self, key, value):
        if not isinstance(value, str):
            return self.database.set(str(key), json.dumps(value, default=date_converter))
        else:
            return self.database.set(str(key), value)

    def append(self, key, more):
        return self.database.append(str(key), more)

    def dump(self):
        return self.database.dump()

def get_config(key: str = None, config_file: str = None, default=None) -> dict:
    global config
    if not key:
        key = xxh32_hexdigest(bytes(config_file))
    if key in config:
        return config[key] or default
    if not config_file:
        return default
    with open(config_file, 'r') as f:
        config[key] = yaml.load(f.read(), Loader=yaml.SafeLoader) or default

    return config[key] or default


def randomstr(length: int) -> str:
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def setup_logging(log_level: int, file_path: str = None) -> None:
    log = logging.getLogger()
    format_str = '%(asctime)s - %(process)d - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if os.isatty(2):
        cformat = '%(log_color)s' + format_str
        colors = {
            'DEBUG': 'reset',
            'INFO': 'bold_blue',
            'WARNING': 'bold_yellow',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red'
        }
        formatter = colorlog.ColoredFormatter(
            cformat, date_format, log_colors=colors)
    else:
        formatter = logging.Formatter(format_str, date_format)

    if log_level > 0:
        if file_path:
            file_handler = logging.StreamHandler(open(file_path, 'a+'))
            file_handler.setFormatter(formatter)
            log.addHandler(file_handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        log.addHandler(stream_handler)
    if log_level == 1:
        log.setLevel(logging.CRITICAL)
    if log_level == 2:
        log.setLevel(logging.ERROR)
    if log_level == 3:
        log.setLevel(logging.WARN)
    if log_level == 4:
        log.setLevel(logging.INFO)
    if log_level >= 5:
        log.setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)


def configure_credentials(RoleName: str, Profile: str = None, Account: str = '*', Region: str = None, RoleSessionName: str = randomstr(10)) -> tuple:
    global credentials
    session = boto3.Session(profile_name=Profile, region_name=Region)
    sts_client = session.client('sts')
    assumedRoleObject = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{Account}:role/{RoleName}",
        RoleSessionName=RoleSessionName
    )
    credentials = assumedRoleObject['Credentials']
    if Region:
        credentials['region'] = Region

    return credentials, sts_client


def get_credentials(RoleName: str, Profile: str = None, Region: str = None, Account: str = '*', RoleSessionName: str = randomstr(10)):
    session = boto3.Session(profile_name=Profile, region_name=Region)
    sts_client = session.client('sts')
    return sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{Account}:role/{RoleName}",
        RoleSessionName=RoleSessionName
    ), sts_client


def get_client(Service: str, Region: str = None, Profile: str = None, RoleName: str = None):
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


def date_converter(o) -> str:
    if isinstance(o, datetime):
        return o.__str__()


def is_json(myjson: str) -> bool:
    try:
        json_object = json.loads(myjson)
    except ValueError:
        return False
    except TypeError:
        return False
    del json_object
    return True


def evaluate_result(data: dict, result: str, account: dict, rule_config: dict, prefix: str = None) -> dict:
    db = Database()
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    record_key = f"{prefix or ''}{rule_config['name']}-{account['id']}"
    if rule_config.get('region'):
        record_key += f"-{rule_config['region']}"
    finding_result = {
        'time': now.isoformat(),
        'compliance': result,
        'data': data,
        'rule': rule_config
    }
    id = xxh32_hexdigest(record_key)
    result_obj = {
        'id': id,
        'key': record_key,
        'rule_name': rule_config['name'],
        'last_result': 'COMPLIES' if result else 'NONCOMPLIANT',
        'alias': account['alias'],
        'account': account['id'],
        'findings':  [finding_result]
    }
    ignore_conf = get_config('ignore', default={})
    ignore_list = [] if 'findings' not in ignore_conf else ignore_conf['findings'].get(
        account['alias'], []) + ignore_conf['findings'].get(account['id'], [])

    for finding in ignore_list:
        if finding['id'] == id and  datetime.strptime(finding['ignore_until'], '%Y-%m-%d') >= datetime.now():
            return dict()

    if db.exists(record_key):
        record = db.get(record_key)
        db.rem(record_key)
        record['last_result'] = result_obj['last_result']
        record['findings'].append(finding_result)
        db.set(record_key, record)
        result_obj = record
    else:
        db.set(record_key, result_obj)
    db.dump()
    return result_obj


def check_rule(inputs: Tuple[dict, dict]) -> bool:
    try:
        account, rule, output = inputs
        log = logging.getLogger()
        rule_name = f"compliance.{rule['name']}"
        rule_obj = importlib.import_module(rule_name)
        rule_fn = getattr(rule_obj, rule['name'])
        log.debug(f"Checking rule {rule['name']} in account {account['alias']} [{account['id']}]")
        data, result = rule_fn(account, rule)
        record = evaluate_result(data, result, account, rule)
        if record and output == 'text':
            report = getattr(rule_obj, 'report')
            text = report(record)
            if record['last_result'] == 'NONCOMPLIANT':
                log.warn(text)
            else:
                log.info(text)
    except Exception as e:
        log.exception(e)
        log.warn(f"Failed on rule {rule['name']} in account {account['alias']} [{account['id']}]")
        return False

    return True


def to_iso8601(when=None, tz=pytz.timezone('UTC')):
    if not when:
        when = datetime.now(tz)
    if not when.tzinfo:
        when = tz.localize(when)
    _when = when.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    return _when[:-8] + _when[-5:]  # remove microseconds


def from_iso8601(when=None, tz=pytz.timezone('UTC')):
    _when = dateutil.parser.parse(when)
    if not _when.tzinfo:
        _when = tz.localize(_when)
    return _when

def report_custom(record: dict) -> str:
    return f"""\t\t\t\t\t\tRULE-NS0-{record['id']}
Rule                  {record['rule_name']}
Result                {record['last_result']}
Rationale             {record['findings'][0]['rule']['purpose']}
Recommended Control   {record['findings'][0]['rule']['control']}
"""

def report_cis(record: dict) -> str:
    return f"""\t\t\t\t\t\tCIS-{'S' if record['findings'][0]['rule']['scored'] else 'NS'}{record['findings'][0]['rule']['level']}-{record['id']}
Rule                  {record['rule_name']}
Result                {record['last_result']}
Rationale             {record['findings'][0]['rule']['purpose']}
Recommended Control   {record['findings'][0]['rule']['control']}
CIS version {record['findings'][0]['rule']['version']} Level {record['findings'][0]['rule']['level']} Recommendation {record['findings'][0]['rule']['recommendation']} ({'Scored' if record['findings'][0]['rule']['scored'] else 'Not Scored'})
"""
