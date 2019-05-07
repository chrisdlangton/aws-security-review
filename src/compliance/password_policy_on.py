import libs
import logging
from compliance import Reconnoitre, BaseScan


def password_policy_on(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    try:
        iam = libs.get_client('iam')
        data = iam.get_account_password_policy().get('PasswordPolicy')
        if data['AllowUsersToChangePassword'] == 'true':
            result = Reconnoitre.COMPLIANT
    except Exception as e:
        if type(e).__name__ == 'NoSuchEntityException':
            data = None
        else:
            raise e
    rule.setData(data)
    rule.setResult(result)
    return rule
