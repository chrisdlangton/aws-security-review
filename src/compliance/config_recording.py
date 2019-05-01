import libs, logging


report = libs.report_custom
def config_recording(account, rule_config):
    result = False

    aws_config = libs.get_client('config')
    data = aws_config.describe_configuration_recorder_status()[
        'ConfigurationRecordersStatus']
    for recorder in data:
        result = result or recorder['recording']

    return data, result
