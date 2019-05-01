import libs
import logging


report = libs.report_cis
def ensure_hardware_mfa_is_enabled_for_the_root_account(account, rule_config):
    result = False

    iam = libs.get_client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    mfa_devices = iam.list_virtual_mfa_devices()['VirtualMFADevices']
    if 'AccountMFAEnabled' in summary and summary['AccountMFAEnabled'] == 1:
        for mfa_device in mfa_devices:
            if 'SerialNumber' in mfa_device:
                result = True

    return summary, result
