import libs, logging
from compliance import Reconnoitre, BaseScan


def enabled_vpc_flow_logs(rule: BaseScan):
    result = False
    ec2 = libs.get_client('ec2')
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        data = ec2.describe_flow_logs(
            Filter=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}])['FlowLogs']
        for flow in data:
            result = result or flow['FlowLogStatus'].lower() == 'active'

    rule.setData(data)
    rule.setResult(Reconnoitre.COMPLIANT if result else Reconnoitre.NON_COMPLIANT)
    return rule
