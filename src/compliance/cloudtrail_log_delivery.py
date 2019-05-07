import libs, logging
from compliance import Reconnoitre, BaseScan


def cloudtrail_log_delivery(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    cloudtrail = libs.get_client('cloudtrail')
    trail = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
    if 'CloudWatchLogsLogGroupArn' in trail:
        result = Reconnoitre.COMPLIANT

    rule.setData(trail)
    rule.setResult(result)
    return rule
