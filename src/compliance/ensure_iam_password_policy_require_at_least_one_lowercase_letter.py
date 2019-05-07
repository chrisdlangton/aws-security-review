import libs
import logging
from compliance import Reconnoitre, BaseScan


def ensure_iam_password_policy_require_at_least_one_lowercase_letter(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['RequireLowercaseCharacters'] == 'true':
        result = Reconnoitre.COMPLIANT
    rule.setData(data)
    rule.setResult(result)
    return rule
