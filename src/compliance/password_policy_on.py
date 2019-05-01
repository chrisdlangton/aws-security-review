import libs
import logging


report = libs.report_custom
def password_policy_on(account, rule_config):
    result = False
    try:
        iam = libs.get_client('iam')
        data = iam.get_account_password_policy().get('PasswordPolicy')
        if data['AllowUsersToChangePassword'] == 'true':
            result = True
    except Exception as e:
        if type(e).__name__ == 'NoSuchEntityException':
            data = None
        else:
            raise e

    return data, result
