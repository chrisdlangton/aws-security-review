import libs, logging


report = libs.report_cis
def ensure_a_support_role_has_been_created_to_manage_incidents_with_aws_support(account, rule_config):
    result = False
    iam = libs.get_client('iam')
    data = iam.list_entities_for_policy(
        PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess', EntityFilter='Role')['PolicyRoles']
    for role in data:
        if role.get('RoleName'):
            result = True

    return data, result
