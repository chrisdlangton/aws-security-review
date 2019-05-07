import libs
import logging
from compliance import Reconnoitre, BaseScan


def ensure_iam_password_policy_prevents_password_reuse(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['PasswordReusePrevention'] >= 24:
        result = Reconnoitre.COMPLIANT
    rule.setData(data)
    rule.setResult(result)
    return rule
