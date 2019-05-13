import libs
import logging
import time
import pytz
from datetime import datetime
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def ensure_access_keys_are_rotated_every_90_days_or_less(rule: BaseScan):
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
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
            if (report['access_key_1_active'] == 'false' and report['access_key_2_active'] == 'false'):
                continue

            user_creation_time = libs.from_iso8601(report['user_creation_time'])
            delta = now - user_creation_time
            if delta.days < 90: # new user
                continue

            if report['access_key_1_active'] == 'true':
                access_key_1_last_rotated = libs.from_iso8601(report['access_key_1_last_rotated'])
                delta = now - access_key_1_last_rotated
                if delta.days > 80:
                    finding = deepcopy(finding_base)
                    finding['description'] += f'. access_key_1_last_rotated {delta.days} days ago'
                    finding['criticality'] = 70
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    finding['finding_type_data'] = {
                        'UserName': report['user'],
                        'Status': 'ACTIVE',
                        'CreatedAt': report['user_creation_time']
                    }
                    rule.setResult(Reconnoitre.COMPLIANT)
                    if delta.days >= 90:
                        finding['criticality'] = 95
                        finding['compliance_status'] = Finding.STATUS_WARNING
                        rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['access_key_2_active'] == 'true':
                access_key_2_last_rotated = libs.from_iso8601(report['access_key_2_last_rotated'])
                delta = now - access_key_2_last_rotated
                if delta.days > 80:
                    finding = deepcopy(finding_base)
                    finding['description'] += f'access_key_2_last_rotated {delta.days} days ago'
                    finding['criticality'] = 70
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    finding['finding_type_data'] = {
                        'UserName': report['user'],
                        'Status': 'ACTIVE',
                        'CreatedAt': report['user_creation_time']
                    }
                    rule.setResult(Reconnoitre.COMPLIANT)
                    if delta.days >= 90:
                        finding['criticality'] = 95
                        finding['compliance_status'] = Finding.STATUS_FAILED
                        rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

        if not rule.result:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 0
            finding['compliance_status'] = Finding.STATUS_PASSED
            finding['finding_type'] = 'Other'
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))

        rule.setData(users)
        return rule
    else:
        time.sleep(3)
        return ensure_access_keys_are_rotated_every_90_days_or_less(rule)
