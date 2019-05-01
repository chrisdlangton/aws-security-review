import helpers
import time
import pytz
from datetime import datetime


def do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(account, rule_config):
    result = False
    data = None

    iam = helpers.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).split(',')

        output = list()
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.split(","))}
            if report['user'] == '<root_account>':
                continue

            if report['access_key_1_last_used_date'] == 'N/A' and report['access_key_1_active'] == 'true':
                data = report
                break

            if report['access_key_2_last_used_date'] == 'N/A' and report['access_key_2_active'] == 'true':
                data = report
                break

        if not data:
            result = True

        return data, result
    else:
        time.sleep(3)
        return do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(account, rule_config)


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
