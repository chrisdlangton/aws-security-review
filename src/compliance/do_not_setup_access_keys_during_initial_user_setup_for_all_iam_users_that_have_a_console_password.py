import libs
import logging
import time
import pytz
from datetime import datetime
from compliance import Reconnoitre, BaseScan


def do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    data = None

    iam = libs.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).decode().split(',')

        output = list()
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.decode().split(","))}
            if report['user'] == '<root_account>':
                continue

            if report['access_key_1_last_used_date'] == 'N/A' and report['access_key_1_active'] == 'true':
                data = report
                break

            if report['access_key_2_last_used_date'] == 'N/A' and report['access_key_2_active'] == 'true':
                data = report
                break

        if not data:
            result = Reconnoitre.COMPLIANT

        rule.setData(data)
        rule.setResult(result)
        return rule
    else:
        time.sleep(3)
        return do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(rule)
