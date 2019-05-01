import os, boto3, random, string, json, sys, pytz, dateutil, logging, colorlog
from os import isatty
from yaml import load, dump
from os import path, getcwd
from datetime import datetime

import database as db


credentials = None
config = None


def get_config(config_file: str = None) -> dict:
    global config

    if not config:
        if not config_file:
            config_file = path.join(path.realpath(getcwd()), 'config.yaml')
        with open(config_file, 'r') as f:
            config = load(f.read())

    return config

def randomstr(length: int) -> str:
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def setup_logging(log_level: int, file_path: str = None) -> None:
    log = logging.getLogger()
    format_str = '%(asctime)s - %(process)d - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if isatty(2):
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


def evaluate_rule(data: dict, result: str, account: dict, rule_config: dict, prefix: str = None) -> list:
    results = []
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    record_key = "{prefix}{label}-{id}".format(
        label=rule_config['name'], id=account['id'], prefix=prefix or '')
    if rule_config.get('region'):
        record_key += f"-{rule_config['region']}"
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
