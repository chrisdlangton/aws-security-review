import libs
import logging
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def ensure_a_support_role_has_been_created_to_manage_incidents_with_aws_support(rule: BaseScan):
    iam = libs.get_client('iam')
    data = iam.list_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess', EntityFilter='Role')['PolicyRoles']
    for role in data:
        finding_base = {
            'account_id': str(rule.account_id),
            'name': f"{rule.__class__.__name__.lower().replace('scan', '')}",
            'region': rule.region,
            'title': rule.name.replace('_', ' '),
            'description': rule.purpose,
            'compliance_status': Finding.STATUS_NOT_AVAILABLE,
            'namespace': 'Software and Configuration Checks',
            'category': 'Industry and Regulatory Standards',
            'classifier': 'CIS AWS Foundations Benchmark',
            'recommendation_text': rule.control,
            'finding_type': 'Other',
            'finding_type_id': 'support-role-exist',
            'finding_type_data': Reconnoitre.fix_custom_data(role),
            'confidence': 100,
            'criticality': 10,
            'severity_normalized': 25
        }
        if rule.recommendation_url:
            finding_base['recommendation_url'] = rule.recommendation_url
        if rule.source_url:
            finding_base['source_url'] = rule.source_url
        if role.get('RoleName'):
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 0
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))
    if not rule.result:
        finding = deepcopy(finding_base)
        finding['confidence'] = 90
        finding['compliance_status'] = Finding.STATUS_FAILED
        rule.setResult(Reconnoitre.NON_COMPLIANT)
        rule.addFinding(Finding(**finding))

    rule.setData(data)
    return rule
