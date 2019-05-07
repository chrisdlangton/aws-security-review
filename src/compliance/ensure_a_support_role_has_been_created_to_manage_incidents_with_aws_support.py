import libs, logging
from compliance import Reconnoitre, BaseScan


def ensure_a_support_role_has_been_created_to_manage_incidents_with_aws_support(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    iam = libs.get_client('iam')
    data = iam.list_entities_for_policy(
        PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess', EntityFilter='Role')['PolicyRoles']
    for role in data:
        if role.get('RoleName'):
            result = Reconnoitre.COMPLIANT

    rule.setData(data)
    rule.setResult(result)
    return rule
