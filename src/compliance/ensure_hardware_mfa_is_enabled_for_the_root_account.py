import libs
import logging
from compliance import Reconnoitre, BaseScan


def ensure_hardware_mfa_is_enabled_for_the_root_account(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    iam = libs.get_client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    mfa_devices = iam.list_virtual_mfa_devices()['VirtualMFADevices']
    if 'AccountMFAEnabled' in summary and summary['AccountMFAEnabled'] == 1:
        for mfa_device in mfa_devices:
            if 'SerialNumber' in mfa_device:
                result = Reconnoitre.COMPLIANT
    rule.setData(summary)
    rule.setResult(result)
    return rule
