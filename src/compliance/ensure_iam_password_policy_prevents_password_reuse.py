import libs
import logging


report = libs.report_cis
def ensure_iam_password_policy_prevents_password_reuse(account, rule_config):
    result = False
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['PasswordReusePrevention'] >= 24:
        result = True

    return data, result
