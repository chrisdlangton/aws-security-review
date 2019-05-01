import libs
import logging


report = libs.report_cis
def ensure_iam_password_policy_requires_minimum_length_of_14_or_greater(account, rule_config):
    result = False
    iam = libs.get_client('iam')
    data = iam.get_account_password_policy().get('PasswordPolicy')
    if data['MinimumPasswordLength'] >= 14:
        result = True

    return data, result
