import libs
import logging
from compliance import Reconnoitre, BaseScan


def ensure_iam_password_policy_expires_passwords_within_90_days_or_less(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['ExpirePasswords'] == 'true' and data['MaxPasswordAge'] <= 90:
        result = Reconnoitre.COMPLIANT
    rule.setData(data)
    rule.setResult(result)
    return rule
