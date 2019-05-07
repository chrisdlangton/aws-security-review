import libs
from compliance import Reconnoitre, BaseScan


def ensure_mfa_is_enabled_for_the_root_account(rule: BaseScan):
    result = Reconnoitre.NON_COMPLIANT

    iam = libs.get_client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    if 'AccountMFAEnabled' in summary:
        if summary['AccountMFAEnabled'] == 1:
            result = Reconnoitre.COMPLIANT
    rule.setData(summary)
    rule.setResult(result)
    return rule
