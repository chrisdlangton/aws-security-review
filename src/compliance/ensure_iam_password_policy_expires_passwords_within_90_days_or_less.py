import libs
import logging


report = libs.report_cis
def ensure_iam_password_policy_expires_passwords_within_90_days_or_less(account, rule_config):
    result = False
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['ExpirePasswords'] == 'true' and data['MaxPasswordAge'] <= 90:
        result = True

    return data, result
