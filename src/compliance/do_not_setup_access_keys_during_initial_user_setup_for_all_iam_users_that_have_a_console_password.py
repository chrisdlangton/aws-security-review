import libs
import logging
import time
import pytz
from datetime import datetime
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(rule: BaseScan):

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

            finding_base = {
                'account_id': str(rule.account_id),
                'name': f"{rule.__class__.__name__.lower().replace('scan', '')}",
                'region': rule.region,
                'title': rule.name.replace('_', ' '),
                'description': rule.purpose,
                'compliance_status': Finding.STATUS_NOT_AVAILABLE,
                'namespace': 'Sensitive Data Identifications',
                'category': 'Security',
                'classifier': 'AWSSecretAccessKey',
                'recommendation_text': rule.control,
                # recommendation_url: str = None,
                'finding_type': 'Other',
                # 'finding_type': 'AwsIamAccessKey',
                'finding_type_id': report['user'],
                # source_url: str = None,
                'confidence': 100,
                'criticality': 80,
                'severity_normalized': 95
            }

            if report['access_key_1_last_used_date'] == 'N/A' and report['access_key_1_active'] == 'true':
                finding = deepcopy(finding_base)
                finding['compliance_status'] = Finding.STATUS_FAILED
                finding['finding_type_data'] = {
                    'UserName': report['user'],
                    'Status': 'ACTIVE',
                    'CreatedAt': report['user_creation_time']
                }
                rule.setResult(Reconnoitre.NON_COMPLIANT)
                rule.addFinding(Finding(**finding))

            if report['access_key_2_last_used_date'] == 'N/A' and report['access_key_2_active'] == 'true':
                finding = deepcopy(finding_base)
                finding['compliance_status'] = Finding.STATUS_FAILED
                finding['finding_type_data'] = {
                    'UserName': report['user'],
                    'Status': 'ACTIVE',
                    'CreatedAt': report['user_creation_time']
                }
                rule.setResult(Reconnoitre.NON_COMPLIANT)
                rule.addFinding(Finding(**finding))

            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 0
            finding['compliance_status'] = Finding.STATUS_PASSED
            finding['finding_type'] = 'Other'
            finding['finding_type_data'] = Reconnoitre.fix_custom_data(report)
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))

        rule.setData(content)
        return rule
    else:
        time.sleep(3)
        return do_not_setup_access_keys_during_initial_user_setup_for_all_iam_users_that_have_a_console_password(rule)
