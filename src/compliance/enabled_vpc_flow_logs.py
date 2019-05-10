import libs
import logging
from copy import deepcopy
from compliance import Reconnoitre, BaseScan, Finding


def enabled_vpc_flow_logs(rule: BaseScan):
    ec2 = libs.get_client('ec2')
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        data = ec2.describe_flow_logs(Filter=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}])['FlowLogs']
        for flow in data:
            rule.setData(data)
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
                'finding_type': 'AwsEc2Vpc',
                'finding_type_id': vpc['VpcId'],
                'resource_type': 'Other',
                'resource_data': Reconnoitre.fix_custom_data(flow),
                # source_url: str = None,
                'confidence': 100,
                'criticality': 74,
                'severity_normalized': 60
            }
            if flow['FlowLogStatus'].lower() != 'active':
                finding = deepcopy(finding_base)
                finding['compliance_status'] = Finding.STATUS_FAILED
                rule.setResult(Reconnoitre.NON_COMPLIANT)
                rule.addFinding(Finding(**finding))
                continue
        if not rule.result:
            finding = deepcopy(finding_base)
            finding['severity_normalized'] = 0
            finding['compliance_status'] = Finding.STATUS_PASSED
            rule.setResult(Reconnoitre.COMPLIANT)
            rule.addFinding(Finding(**finding))

    return rule
