import libs
from compliance import Reconnoitre, BaseScan


FIELD_ACCESS_KEY_1_ACTIVE = 8
FIELD_ACCESS_KEY_2_ACTIVE = 13


def ensure_no_root_account_access_key_exists(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    iam = libs.get_client('iam')
    content = iam.get_credential_report()['Content']
    users = content.splitlines()
    # Look for the '<root_account>' user value and determine whether access keys are active.
    for u in users:
        user = u.decode()
        if '<root_account>' in user:
            user_values = user.split(',')
            if user_values[FIELD_ACCESS_KEY_1_ACTIVE].lower() == 'false' and user_values[FIELD_ACCESS_KEY_2_ACTIVE].lower() == 'false':
                result = Reconnoitre.COMPLIANT
    rule.setData(content)
    rule.setResult(result)
    return rule
