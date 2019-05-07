import libs
import logging
import pytz
from datetime import datetime
from compliance import Reconnoitre, CustomScan


def iam_key_max_age_days(rule: CustomScan):
    result = Reconnoitre.NON_COMPLIANT

    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    iam = libs.get_client('iam')
    for user in iam.list_users().get('Users'):
        for data in iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata'):
            rule_value = rule.attributes.get('threshold')
            create_date = data['CreateDate']
            delta = now - create_date
            if data['Status'] == 'Active':
                if delta.days <= rule_value:
                    result = Reconnoitre.COMPLIANT
                else:
                    break

    rule.setData(data)
    rule.setResult(result)
    return rule
