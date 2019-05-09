import libs
import logging
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def cloudtrail_log_delivery(rule: BaseScan):
    cloudtrail = libs.get_client('cloudtrail')
    trails = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
    for trail in trails:
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
            # recommendation_url: str = None,
            'finding_type': 'AwsCloudTrailTrail',
            'finding_type_id': 'cloudtrail-log-delivery',
            'resource_type': 'Other',
            'resource_data': Reconnoitre.fix_custom_data(trail),
            # source_url: str = None,
            'confidence': 100,
            'criticality': 74,
            'severity_normalized': 85
        }

        if 'CloudWatchLogsLogGroupArn' in trail and 'S3BucketName' in trail:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 0
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))
            continue
        elif 'CloudWatchLogsLogGroupArn' in trail:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 1
            finding['confidence'] = 50
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))
            continue
        elif 'S3BucketName' in trail:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 1
            finding['confidence'] = 50
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))
            continue
        elif 'SnsTopicARN' in trail:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 1
            finding['confidence'] = 25
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))
            continue
        if rule.result != Reconnoitre.NON_COMPLIANT:
            rule.setResult(Reconnoitre.NON_COMPLIANT)
            finding = deepcopy(finding_base)
            finding['confidence'] = 90
            finding['compliance_status'] = Finding.STATUS_FAILED
            rule.addFinding(Finding(**finding))

    rule.setData(trails)
    return rule
