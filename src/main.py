#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""AWS Security Scanner.

This module evaluates the rules defined by rules.yaml and executes the
coresponding test proceedures in ./complience.
Supportting the CIS AWS Benchmark, you can better understand your AWS
Account security posture and apply recommended controls.
You may follow any single test proceedure to apply your own custom
proceedures

Example:
    $ ./src/main.py -vvvv


Attributes:
    --config-file (string): defaults to config.yaml
    --log-file (string): defaults to stdout

Todo:
    * Finish CIS test proceedures
    * refactor to provide better layout of complience directory
"""
import boto3, pytz, importlib, logging, argparse
from datetime import datetime
from yaml import load, dump

import database as db
import helpers
from compliance import rules


def main():
    log = logging.getLogger()
    c = helpers.get_config()
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    log.info(f"Started at {now}")
    db.deldb()

    for account in c['accounts']:
        id = account['id']
        log.info(f'Scanning AWS Account: {id}')

        role = None
        profile = None
        if account.get('assumeRole'):
            role = account['assumeRole']
        if account.get('profile'):
            profile = account['profile']

        helpers.configure_credentials(role, profile, id)

        for rule in rules:
            if not rule.get('regions'):
                check_rule(rule)

        for rule in rules:
            if rule.get('regions'):
                for region in rule.get('regions'):
                    helpers.configure_credentials(role, profile, id, region)
                    rule['region'] = region
                    check_rule(rule)


def check_rule(rule: str) -> bool:
    rule_name = f"compliance.{rule['name']}"
    rule_obj = importlib.import_module(rule_name)
    rule_fn = getattr(rule_obj, rule['name'])
    try:
        data, result = rule_fn(account, rule)
    except Exception as e:
        log.exception(e)
        return False

    results = helpers.evaluate_rule(data, result, account, rule)
    if results:
        report = getattr(rule_obj, 'report')
        for result in results:
            record = db.get(result)
            if record['last_result'] == 'NONCOMPLIANT':
                report(record)
                break
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-l', '--log-file', default=None, help='absolute path to log file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    helpers.setup_logging(log_level, file_path=args.log_file)
    c = helpers.get_config(config_file=args.config_file)

    main()
    db.dump()
