import libs
import logging


report = libs.report_cis
def ensure_iam_instance_roles_are_used_for_aws_resource_access_from_instances(account, rule_config):
    result = False
    ec2 = libs.get_client('ec2')
    data = list()
    instances = list()
    for reservation in ec2.describe_instances()['Reservations']:
        for instance in reservation['Instances']:
            instances.append(instance)
    for instance in instances:
        if not instance.get('IamInstanceProfile'):
            data.append(instance)

    if not data:
        result = True

    return data, result
