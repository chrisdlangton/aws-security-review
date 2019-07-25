import libs
import logging
import time
import pytz
from datetime import datetime
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def ensure_credentials_unused_for_90_days_or_greater_are_disabled(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

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

            if (report['password_enabled'] == 'false' and
                report['cert_1_active'] == 'false' and
                    report['cert_2_active'] == 'false'):
                continue

            user_creation_time = libs.from_iso8601(report['user_creation_time'])
            delta = now - user_creation_time
            if delta.days < 90:
                continue

            compliant_days = rule.settings.get('compliant_days', 90)
            warning_days = compliant_days - rule.settings.get('warning_days_prior', 10)
            finding_base = {
                'account_id': str(rule.account_id),
                'name': f"{rule.__class__.__name__.lower().replace('scan', '')}",
                'region': rule.region,
                'title': rule.name.replace('_', ' '),
                'description': rule.purpose,
                'compliance_status': Finding.STATUS_NOT_AVAILABLE,
                'namespace': 'Sensitive Data Identifications',
                'category': 'Passwords',
                'classifier': 'AWSIamUser',
                'recommendation_text': rule.control,
                # 'finding_type': 'Other',
                'finding_type': 'AwsIamUser',
                'finding_type_id': report['user'],
                'confidence': 100,
                'criticality': 75,
                'severity_normalized': 60
            }
            if rule.recommendation_url:
                finding_base['recommendation_url'] = rule.recommendation_url
            if rule.source_url:
                finding_base['source_url'] = rule.source_url

            if report['password_enabled'] == 'true':
                password_last_changed = libs.from_iso8601(report['password_last_changed'])
                delta = now - password_last_changed
                finding = deepcopy(finding_base)
                finding['description'] += f'password_last_changed {delta.days} days ago'
                finding['finding_type_data'] = {
                    'UserName': report['user'],
                    'PasswordLastChanged': report['password_last_changed']
                }
                if delta.days >= warning_days:
                    finding['compliance_status'] = Finding.STATUS_WARNING
                    rule.setResult(Reconnoitre.COMPLIANT)
                    if delta.days >= compliant_days:
                        finding['compliance_status'] = Finding.STATUS_FAILED
                        rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['cert_1_active'] == 'true':
                cert_1_last_rotated = libs.from_iso8601(report['cert_1_last_rotated'])
                delta = now - cert_1_last_rotated
                finding = deepcopy(finding_base)
                finding['description'] += f'cert_1_last_rotated {delta.days} days ago'
                finding['finding_type_data'] = {
                    'UserName': report['user'],
                    'CertLastRotated': report['cert_1_last_rotated']
                }
                if delta.days >= warning_days:
                    finding['compliance_status'] = Finding.STATUS_WARNING
                    rule.setResult(Reconnoitre.COMPLIANT)
                    if delta.days >= compliant_days:
                        finding['compliance_status'] = Finding.STATUS_FAILED
                        rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['cert_2_active'] == 'true':
                cert_2_last_rotated = libs.from_iso8601(report['cert_2_last_rotated'])
                delta = now - cert_2_last_rotated
                finding = deepcopy(finding_base)
                finding['description'] += f'cert_2_last_rotated {delta.days} days ago'
                finding['finding_type_data'] = {
                    'UserName': report['user'],
                    'CertLastRotated': report['cert_2_last_rotated']
                }
                if delta.days >= warning_days:
                    finding['compliance_status'] = Finding.STATUS_WARNING
                    rule.setResult(Reconnoitre.COMPLIANT)
                    if delta.days >= compliant_days:
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
        return ensure_credentials_unused_for_90_days_or_greater_are_disabled(rule)
