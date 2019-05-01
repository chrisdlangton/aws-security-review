import libs
import logging
import pytz
from datetime import datetime


report = libs.report_custom
def iam_key_max_age_days(account, rule_config):
    result = False

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    iam = libs.get_client('iam')
    for user in iam.list_users().get('Users'):
        for data in iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata'):
            result = False
            rule_value = rule_config['threshold']
            create_date = data['CreateDate']
            delta = now - create_date

            if delta.days <= rule_value and data['Status'] == 'Active':
                result = True
    return data, result
