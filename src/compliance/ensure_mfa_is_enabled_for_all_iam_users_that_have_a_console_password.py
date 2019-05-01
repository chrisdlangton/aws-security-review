import libs
import logging
import time
import pytz
from datetime import datetime


report = libs.report_cis
def ensure_mfa_is_enabled_for_all_iam_users_that_have_a_console_password(account, rule_config):
    result = False

    iam = libs.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).decode().split(',')
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.decode().split(","))}
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
