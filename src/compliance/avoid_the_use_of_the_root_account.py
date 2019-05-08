import libs
import time
import pytz
import logging
import json
from copy import deepcopy
from datetime import datetime
from compliance import Reconnoitre, BaseScan, Finding
from xxhash import xxh64_hexdigest


def avoid_the_use_of_the_root_account(rule: BaseScan):
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    iam = libs.get_client('iam')
    response = iam.generate_credential_report()['State']
    if response == 'COMPLETE':
        content = iam.get_credential_report()['Content']
        users = content.splitlines()
        cols = users.pop(0).decode().split(',')
        for s in users:
            report = {cols[k]: item for k, item in enumerate(s.decode().split(","))}
            if report['user'] != '<root_account>':
                continue

            dts = datetime.utcnow()
            epochtime = round(time.mktime(dts.timetuple()) + dts.microsecond/1e6)
            finding_id = xxh64_hexdigest(f'{rule.name}{epochtime}', seed=20141025)
            finding_name = f"reconnoitre-{rule.__class__.__name__.lower().replace('scan', '')}-{finding_id}"
            finding_base = {
                'account_id': str(rule.account_id),
                'id_str': finding_id,
                'generator_id': finding_name,
                'region': rule.region,
                'title': rule.name.replace('_', ' '),
                'description': rule.purpose,
                'compliance_status': Finding.STATUS_PASSED,
                'namespace': 'Unusual Behaviors',
                'category': 'User',
                'classifier': 'root',
                'recommendation_text': rule.control,
                # recommendation_url: str = None,
                'finding_type': 'AwsIamUser',
                'finding_type_id': 'root',
                'resource_type': 'Other',
                'resource_data': report,
                # source_url: str = None,
                'confidence': 100,
                'criticality': 99,
                'severity_normalized': 0
            }
            password_last_used = libs.from_iso8601(report['password_last_used'])
            delta = now - password_last_used
            if delta.days <= rule.settings.get('password_used'):
                finding = deepcopy(finding_base)
                finding['finding_type_id'] = 'root-password-used'
                finding['severity_normalized'] = 90
                finding['compliance_status'] = Finding.STATUS_FAILED
                rule.setResult(Reconnoitre.NON_COMPLIANT)
                rule.addFinding(Finding(**finding))

            if report['access_key_1_active'] == 'true':
                access_key_1_last_used_date = libs.from_iso8601(report['access_key_1_last_used_date'])
                delta = now - access_key_1_last_used_date
                if delta.days <= rule.settings.get('access_key_used'):
                    finding = deepcopy(finding_base)
                    finding['finding_type_id'] = 'root-accesskey-used'
                    finding['severity_normalized'] = 99
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['access_key_2_active'] == 'true':
                access_key_2_last_used_date = libs.from_iso8601(
                    report['access_key_2_last_used_date'])
                delta = now - access_key_2_last_used_date
                if delta.days <= rule.settings.get('access_key_used'):
                    finding = deepcopy(finding_base)
                    finding['finding_type_id'] = 'root-accesskey-used'
                    finding['severity_normalized'] = 99
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['cert_1_active'] == 'true':
                cert_1_last_rotated = libs.from_iso8601(report['cert_1_last_rotated'])
                delta = now - cert_1_last_rotated
                if delta.days <= rule.settings.get('certificate_rotated'):
                    finding = deepcopy(finding_base)
                    finding['finding_type_id'] = 'root-certificate-rotated'
                    finding['severity_normalized'] = 65
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))

            if report['cert_2_active'] == 'true':
                cert_2_last_rotated = libs.from_iso8601(
                    report['cert_2_last_rotated'])
                delta = now - cert_2_last_rotated
                if delta.days <= rule.settings.get('certificate_rotated'):
                    finding = deepcopy(finding_base)
                    finding['finding_type_id'] = 'root-certificate-rotated'
                    finding['severity_normalized'] = 65
                    finding['compliance_status'] = Finding.STATUS_FAILED
                    rule.setResult(Reconnoitre.NON_COMPLIANT)
                    rule.addFinding(Finding(**finding))
            break

        if not rule.result:
            rule.setResult(Reconnoitre.COMPLIANT)

        rule.setData(content)
        return rule
    else:
        time.sleep(3)
        return avoid_the_use_of_the_root_account(rule)
