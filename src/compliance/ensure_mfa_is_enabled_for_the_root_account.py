import libs

report = libs.report_cis
def ensure_mfa_is_enabled_for_the_root_account(account, rule_config):
    result = False

    iam = libs.get_client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    if 'AccountMFAEnabled' in summary:
        if summary['AccountMFAEnabled'] == 1:
            result = True

    return summary, result
