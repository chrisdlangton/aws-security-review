import helpers


def cloudtrail_log_delivery(account, rule_config):
    result = False

    cloudtrail = helpers.get_client('cloudtrail')
    trail = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
    if 'CloudWatchLogsLogGroupArn' in trail:
        result = True

    return trail, result


def report(record):
    print """
Rule                  {rule}
Result                {result} in region {region}
Rationale             {desc}
Recommended Control   {control}""".format(
        rule=record['rule']['name'],
        result=record['last_result'],
        desc=record['rule']['purpose'],
        control=record['rule']['control'],
        region=record['rule']['region']
    )
