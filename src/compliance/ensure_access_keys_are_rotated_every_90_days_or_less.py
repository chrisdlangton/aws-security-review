import libs, logging
import time
import pytz
from datetime import datetime
from compliance import Reconnoitre, BaseScan


def ensure_access_keys_are_rotated_every_90_days_or_less(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
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

            if (report['access_key_1_active'] == 'false' and
                    report['access_key_2_active'] == 'false'):
                continue

            user_creation_time = libs.from_iso8601(
                report['user_creation_time'])
            delta = now - user_creation_time
            if delta.days < 90:
                continue

            if report['access_key_1_active'] == 'true':
                access_key_1_last_rotated = libs.from_iso8601(
                    report['access_key_1_last_rotated'])
                delta = now - access_key_1_last_rotated
                if delta.days >= 90:
                    output.append(
                        'access_key_1_last_rotated %d days ago' % delta.days)
                    break

            if report['access_key_2_active'] == 'true':
                access_key_2_last_rotated = libs.from_iso8601(
                    report['access_key_2_last_rotated'])
                delta = now - access_key_2_last_rotated
                if delta.days >= 90:
                    output.append(
                        'access_key_2_last_rotated %d days ago' % delta.days)
                    break

            result = Reconnoitre.COMPLIANT
            break
        # print '\n'.join(output)
        rule.setData(content)
        rule.setResult(result)
        return rule
    else:
        time.sleep(3)
        return ensure_access_keys_are_rotated_every_90_days_or_less(rule)
