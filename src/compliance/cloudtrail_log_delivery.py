import libs, logging


report = libs.report_custom
def cloudtrail_log_delivery(account, rule_config):
    result = False

    cloudtrail = libs.get_client('cloudtrail')
    trail = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
    if 'CloudWatchLogsLogGroupArn' in trail:
        result = True

    return trail, result
