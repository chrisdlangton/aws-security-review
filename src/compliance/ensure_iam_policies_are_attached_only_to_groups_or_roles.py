import helpers


def ensure_iam_policies_are_attached_only_to_groups_or_roles(account, rule_config):
    result = False

    iam = helpers.get_client('iam')
    users = [v['UserName'] for v in iam.list_users()['Users']]
    data = list()
    for username in users:
        policies = iam.list_user_policies(UserName=username)['PolicyNames']
        if policies.__len__ != 0:
            for p in policies:
                d = iam.get_user_policy(UserName=username, PolicyName=p)
                del d['ResponseMetadata']
                data.append(d)

    if data.__len__ == 0:
        result = True

    return data, result


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
