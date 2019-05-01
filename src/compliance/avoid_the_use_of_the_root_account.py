import helpers
import time
import pytz
from datetime import datetime


def avoid_the_use_of_the_root_account(account, rule_config):
    result = False

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    iam = helpers.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).split(',')
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.split(","))}
            if report['user'] != '<root_account>':
                continue

            password_last_used = helpers.from_iso8601(
                report['password_last_used'])
            delta = now - password_last_used
            if delta.days <= rule_config['settings']['password_used']:
                break

            if report['access_key_1_active'] == 'true':
                access_key_1_last_used_date = helpers.from_iso8601(
                    report['access_key_1_last_used_date'])
                delta = now - access_key_1_last_used_date
                if delta.days <= rule_config['settings']['access_key_used']:
                    break

            if report['access_key_2_active'] == 'true':
                access_key_2_last_used_date = helpers.from_iso8601(
                    report['access_key_2_last_used_date'])
                delta = now - access_key_2_last_used_date
                if delta.days <= rule_config['settings']['access_key_used']:
                    break

            if report['cert_1_active'] == 'true':
                cert_1_last_rotated = helpers.from_iso8601(
                    report['cert_1_last_rotated'])
                delta = now - cert_1_last_rotated
                if delta.days <= rule_config['settings']['certificate_rotated']:
                    break

            if report['cert_2_active'] == 'true':
                cert_2_last_rotated = helpers.from_iso8601(
                    report['cert_2_last_rotated'])
                delta = now - cert_2_last_rotated
                if delta.days <= rule_config['settings']['certificate_rotated']:
                    break

            result = True
            break

        return content, result
    else:
        time.sleep(3)
        return avoid_the_use_of_the_root_account(account, rule_config)


def report(record):
    print """
CIS version {version} Level {level} Recommendation {recommendation} ({scored})
Rule                  {rule}
Result                {result}
Rationale             {desc}
Recommended Control   {control}
""".format(
        rule=record['rule']['name'],
        result=record['last_result'],
        desc=record['rule']['purpose'],
        control=record['rule']['control'],
        version=record['rule']['version'],
        level=record['rule']['level'],
        recommendation=record['rule']['recommendation'],
        scored='Scored' if record['rule']['scored'] else 'Not Scored'
    )
