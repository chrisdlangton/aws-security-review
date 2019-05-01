import libs, logging


report = libs.report_custom
def enabled_vpc_flow_logs(account, rule_config):
    result = False
    ec2 = libs.get_client('ec2')
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        data = ec2.describe_flow_logs(
            Filter=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}])['FlowLogs']
        for flow in data:
            result = result or flow['FlowLogStatus'].lower() == 'active'

    return data, result
