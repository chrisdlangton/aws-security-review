import helpers
import time
import pytz
from datetime import datetime


def ensure_mfa_is_enabled_for_all_iam_users_that_have_a_console_password(account, rule_config):
    result = False

    iam = helpers.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).split(',')
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.split(","))}
            if report['user'] == '<root_account>':
                continue

            if report['password_enabled'] == 'true' and report['mfa_active'] != 'true':
                break

            result = True
            break

        return content, result
    else:
        time.sleep(3)
        return ensure_mfa_is_enabled_for_all_iam_users_that_have_a_console_password(account, rule_config)


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
