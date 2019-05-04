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
    $ ./src/main.py -vvvv --debug --ignore-file ignores.yaml

Attributes:

  -h --help             show this help message and exit
  -c --config-file CONFIG_FILE
                        absolute path to config file
  -r --rules-file RULES_FILE
                        absolute path to rules config file
  -i --ignore-file IGNORE_FILE
                        absolute path to ignore config file
  -l --log-file LOG_FILE
                        absolute path to log file
  -t --test TEST
                        Comma seperated Rule name to test
  -o --output OUTPUT
                        output options: text | json
  --verbose -v
                        use -vvvvv for debug output, remove a "v" for quieter outputs
  --debug
                        avoids multiprocessing for cleaner stack traces but may be slower

"""
import boto3
import pytz
import logging
import argparse
import multiprocessing
import gc
import libs
from datetime import datetime
from yaml import load, dump
from json import dumps
from libs import Database


def main(debug, test, output):
    log = logging.getLogger()
    db = Database()
    c = libs.get_config('config')
    r = libs.get_config('rules')
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    log.info(f"Started at {now}")
    if debug:
        db.deldb()
    queue = []
    rules = []
    for account in c['accounts']:
        id = account['id']
        log.info(f'Scanning AWS Account: {id}')
        if 'assumeRole' in account:
            log.info(f'Using IAM Role: {account["assumeRole"]}')
        role = None
        profile = None
        if account.get('assumeRole'):
            role = account['assumeRole']
        if account.get('profile'):
            profile = account['profile']

        ignore_conf = libs.get_config('ignore', default={})
        ignore_list = [] if 'rules' not in ignore_conf else ignore_conf['rules'].get(
            account['alias'], []) + ignore_conf['rules'].get(account['id'], [])

        if test:
            for rule in r['cis']+r['custom']:
                if rule['name'] in test.split(',') and rule['name'] not in ignore_list:
                    rules.append(rule)
        else:
            if c['compliance'].get('custom_rules') and 'custom' in r:
                rules += r['custom']
            if 'cis' in r:
                rules += [x for x in r['cis'] if x.get('level') <= c['compliance'].get('cis_level', 2)]

        libs.configure_credentials(role, profile, id)
        for rule in rules:
            if not rule.get('regions'):
                queue.append((account, rule, output))

        for rule in rules:
            if rule.get('regions'):
                for region in rule.get('regions'):
                    rule['region'] = region
                    queue.append((account, rule, output))
    try:
        if debug:
            for item in queue:
                libs.check_rule(item)
        else:
            gc.collect()
            p = multiprocessing.Pool(processes=multiprocessing.cpu_count())
            p.map(libs.check_rule, queue)
            p.close()
            p.join()
    except Exception as e:
        log.exception(e)

    db = Database()
    if output == 'json':
        report = []
        for record in db.getall():
            ignore = False
            if ignore_list and 'findings' in ignore_list:
                for finding in ignore_list['findings']:
                    if finding['id'] == record['id']:
                        ignore = True
                        break
            if not ignore:
                report.append(record)
        print(dumps(report, indent=2, sort_keys=True))
    elif output == 'text':
        result_agg = {
            'NONCOMPLIANT': 0,
            'COMPLIES': 0,
        }
        for record in db.getall():
            result_agg[record['last_result']] += 1
        total = result_agg['NONCOMPLIANT'] + result_agg['COMPLIES']
        if result_agg['NONCOMPLIANT'] != 0:
            log.error(f"Scanned {total} Rules with {result_agg['NONCOMPLIANT']} NONCOMPLIANT issues found")
        else:
            log.info(f"COMPLIANT ({total} Rules)")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-r', '--rules-file', default='rules.yaml', help='absolute path to rules config file')
    parser.add_argument('-l', '--log-file', default=None, help='absolute path to log file')
    parser.add_argument('-i', '--ignore-file', default=None, help='absolute path to ignore file')
    parser.add_argument('-t', '--test', type=str, default=None, help='Comma seperated Rule name to test')
    parser.add_argument('-o', '--output', type=str, default='text', help='output options: text | json')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='use -vvvvv for debug output, remove a "v" for quieter outputs')
    parser.add_argument('--debug', action='store_true', help='avoids multiprocessing for cleaner stack traces but may be slower')
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    libs.setup_logging(log_level, file_path=args.log_file)
    libs.get_config(config_file=args.config_file, key='config')
    libs.get_config(config_file=args.rules_file, key='rules')
    if args.ignore_file:
        libs.get_config(config_file=args.ignore_file, key='ignore')
    main(debug=args.debug, test=args.test, output=args.output)
