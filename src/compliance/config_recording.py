import libs, logging
from compliance import Reconnoitre, BaseScan


def config_recording(rule: BaseScan):
    result = False

    aws_config = libs.get_client('config')
    data = aws_config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
    for recorder in data:
        if recorder['recording']:
            result = result or recorder['recording']

    rule.setData(data)
    rule.setResult(Reconnoitre.COMPLIANT if result else Reconnoitre.NON_COMPLIANT)
    return rule
