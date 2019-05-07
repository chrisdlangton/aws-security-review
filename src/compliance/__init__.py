import logging
import libs
import importlib
from typing import Tuple


class BaseScan:
    def __init__(self, account: dict, rule_config: dict):
        self.data = None
        self.result = None
        self.findings = []
        self.version = rule_config.get('version', None)
        self.purpose = rule_config.get('purpose')
        self.control = rule_config.get('control')
        self.region = rule_config.get('region', None)
        self.account_alias = account.get('alias', None)
        name = rule_config.get('name')
        account_id = account.get('id')
        assert isinstance(name, str)
        assert isinstance(account_id, int)
        self.name = name
        self.account_id = account_id

    def setData(self, data) -> None:
        self.data = data

    def setRegion(self, region: str) -> None:
        self.region = region

    def setResult(self, result: str) -> None:
        if result not in [
                Reconnoitre.COMPLIANT, Reconnoitre.NON_COMPLIANT,
                Reconnoitre.NOT_APPLICABLE
        ]:
            raise AssertionError(f'bad result: {result}')
        self.result = result

    def addFinding(self, data: dict):
        pass

    def format_text(self) -> str:
        pass

    def format_cvrf(self) -> dict:
        pass

    def format_stix(self) -> dict:
        pass

    def format_json(self) -> dict:
        pass

    def format_aws_security_hub(self) -> dict:
        pass


class CustomScan(BaseScan):
    def __init__(self, account: dict, rule_config: dict):
        attributes = rule_config.get('attributes', {})
        assert isinstance(attributes, dict)
        self.attributes = attributes
        super().__init__(account, rule_config)


class CISScan(BaseScan):
    def __init__(self, account: dict, rule_config: dict):
        self.recommendation = rule_config.get('recommendation')
        settings = rule_config.get('settings', {})
        scored = rule_config.get('scored')
        level = rule_config.get('level')
        assert isinstance(settings, dict)
        assert isinstance(scored, bool)
        assert isinstance(level, int)
        self.settings = settings
        self.level = level
        self.scored = scored
        super().__init__(account, rule_config)


class Reconnoitre:
    NOT_APPLICABLE = 'NOT_APPLICABLE'
    NON_COMPLIANT = 'NON_COMPLIANT'
    COMPLIANT = 'COMPLIANT'

    @staticmethod
    def prepare_queue(rules: list, account: list, ignore_list: list, mode: str) -> list:
        c = libs.get_config('config')
        queue = []
        # pick configured cis level rules only
        if mode == 'cis':
            rules += [
                x for x in rules
                if x.get('level') <= c['compliance'].get('cis_level', 2)
            ]

        for r in rules:
            if mode == 'custom':
                rule = CustomScan(account, r)
            if mode == 'cis':
                rule = CISScan(account, r)
            if r.get('regions'):
                for region in r.get('regions'):
                    rule.setRegion(region)
                    queue.append(rule)
            else:
                queue.append(rule)
        return queue

    @staticmethod
    def check_rule(rule: BaseScan):
        log = logging.getLogger()
        try:
            rule_name = f"compliance.{rule.name}"
            rule_obj = importlib.import_module(rule_name)
            rule_fn = getattr(rule_obj, rule.name)
            log.debug(
                f"Checking rule {rule.name} in account {rule.account_id}{'' if not rule.account_id else '['+str(rule.account_id)+']'}"
            )
            return rule_fn(rule)

        except Exception as e:
            log.exception(e)
            log.warn(f"Failed on rule {rule.name} in account {rule.account_id}")
