import libs, logging
from compliance import Reconnoitre, BaseScan


def ensure_iam_policies_are_attached_only_to_groups_or_roles(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    iam = libs.get_client('iam')
    users = [v['UserName'] for v in iam.list_users()['Users']]
    data = list()
    for username in users:
        policies = iam.list_user_policies(UserName=username)['PolicyNames']
        if policies.__len__ != 0:
            for p in policies:
                d = iam.get_user_policy(UserName=username, PolicyName=p)
                del d['ResponseMetadata']
                data.append(d)

    if data.__len__ == 0:
        result = Reconnoitre.COMPLIANT
    rule.setData(data)
    rule.setResult(result)
    return rule
