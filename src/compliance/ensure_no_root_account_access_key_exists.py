import helpers


FIELD_ACCESS_KEY_1_ACTIVE = 8
FIELD_ACCESS_KEY_2_ACTIVE = 13


def ensure_no_root_account_access_key_exists(account, rule_config):
    result = False

    iam = helpers.get_client('iam')
    content = iam.get_credential_report()['Content']
    users = content.splitlines()
    # Look for the '<root_account>' user value and determine whether access keys are active.
    for user in users:
        if '<root_account>' in user:
            user_values = user.split(',')
            if user_values[FIELD_ACCESS_KEY_1_ACTIVE].lower() == 'false' and user_values[FIELD_ACCESS_KEY_2_ACTIVE].lower() == 'false':
                result = True

    return content, result


def report(record):
    print """
CIS version {version} Level {level} Recommendation {recommendation} ({scored})
Rule                  {rule}
Result                {result}
Rationale             {desc}
Recommended Control   {control}
""".format(
        rule=record['rule']['name'],
        result=record['last_result'],
        desc=record['rule']['purpose'],
        control=record['rule']['control'],
        version=record['rule']['version'],
        level=record['rule']['level'],
        recommendation=record['rule']['recommendation'],
        scored='Scored' if record['rule']['scored'] else 'Not Scored'
    )
