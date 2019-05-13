import logging
import libs
import importlib
import json
import pytz
from datetime import datetime
from xxhash import xxh64_hexdigest


class Finding:
    STATUS_PASSED = 'PASSED'
    STATUS_WARNING = 'WARNING'
    STATUS_FAILED = 'FAILED'
    STATUS_NOT_AVAILABLE = 'NOT_AVAILABLE'

    def __init__(
            self,
            account_id: int,
            region: str,
            title: str,
            description: str,
            compliance_status: str,
            name: str,
            namespace: str,
            category: str,  # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html#securityhub-findings-format-type-taxonomy
            classifier: str,
            recommendation_text: str,
            finding_type: str,
            finding_type_id: str,
            finding_type_data: dict = {},
            recommendation_url: str = None,
            source_url: str = None,
            confidence: int = 100,
            criticality: int = 50,
            severity_normalized: int = 0):
        if compliance_status.upper() not in [
                'PASSED', 'WARNING', 'FAILED', 'NOT_AVAILABLE'
        ]:
            raise AssertionError(f'bad compliance_status {compliance_status}')
        if not 0 <= confidence <= 100:
            raise AssertionError(
                f'provided confidence {confidence} must be between 0-100')
        if not 0 <= criticality <= 100:
            raise AssertionError(
                f'provided criticality {criticality} must be between 0-100')
        if namespace not in [
                'Software and Configuration Checks', 'TTPs', 'Effects',
                'Unusual Behaviors', 'Sensitive Data Identifications'
        ]:
            raise AssertionError(f'bad namespace {namespace}')
        if not region:
            region = 'ap-southeast-2'
        self.compliance_status = compliance_status
        self.confidence = confidence
        self.created_at = libs.aws_iso8601()
        self.criticality = criticality
        self.description = description
        self.account_id = account_id
        self.region = region
        self.product_arn = f'arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default'
        self.recommendation_text = recommendation_text
        self.recommendation_url = recommendation_url
        self.schema_version = '2018-10-08'
        self.severity_normalized = severity_normalized
        self.source_url = source_url
        self.name = name
        self.title = title
        self.types = f'{namespace}/{category}/{classifier}'
        self.finding_type = finding_type
        self.finding_type_id = finding_type_id
        self.finding_type_data = finding_type_data

    def toString(self):
        return f"""                                 {self._make_generator_id()}
        Rule:                   {self.title}
        Description:            {self.description}
        Status:                 {self.compliance_status}
        Account:                {self.account_id} [{self.region}]
        Criticality:            {self.criticality}
        Confidence:             {self.confidence}
        Severity Normalised:    {self.severity_normalized}
        """

    def toDict(self):
        finding = {
            'ProductFields': {
                'Service_Name': 'Reconnoitre',
                'd2vi/reconnoitre/company': 'd2Vi',
                'd2vi/reconnoitre/version': '0.0.1'
            },
            'AwsAccountId': self.account_id,
            'Compliance': {
                'Status': self.compliance_status
            },
            'Confidence': self.confidence,
            'CreatedAt': self.created_at,
            'Criticality': self.criticality,
            'Description': self.description[:1024],
            'GeneratorId': self._make_generator_id()[:512],
            'Id': self._make_id()[:512],
            'ProductArn': self.product_arn,
            'Remediation': {
                'Recommendation': {}
            },
            'SchemaVersion': self.schema_version,
            'Severity': {
                'Normalized': self.severity_normalized
            },
            'Title': f'[Reconnoitre] {self.title}'[:256],
            'Types': [self.types],
            'UpdatedAt': self.created_at,
            'Resources': []
        }
        if self.recommendation_text:
            finding['Remediation']['Recommendation']['Text'] = self.recommendation_text[:512]
        if self.recommendation_url:
            finding['Remediation']['Recommendation']['Url'] = self.recommendation_url
        if self.source_url:
            finding['SourceUrl'] = self.source_url
        resource = {
            'Type': self.finding_type,
            'Id': self.finding_type_id,
            'Details': {
                self.finding_type: self.finding_type_data
            }
        }
        if self.region:
            resource['Region'] = self.region
        finding['Resources'].append(resource)

        return finding

    def __repr__(self):
        return json.dumps(self.toDict(), indent=2)

    def _make_generator_id(self):
        return f'reconnoitre-{self.name}-{Reconnoitre.make_finding_id(self.title)}'

    def _make_id(self):
        return f'{self.region}/{self.account_id}/{Reconnoitre.make_finding_id(self.title)}'


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

    def addFinding(self, finding: Finding):
        self.findings.append(finding)

    def format_cvrf(self) -> dict:
        pass

    def format_stix(self) -> dict:
        pass

    def format_json(self, indent=None) -> list:
        findings = []
        for finding in self.findings:
            findings.append(finding.toDict())
        if indent:
            print(json.dumps(findings, indent=indent, sort_keys=True, default=libs.date_converter))
        else:
            print(json.dumps(findings, sort_keys=True, default=libs.date_converter))
        return findings

    @staticmethod
    def securityhub_findings(archived:bool = False, findings: list = []) -> list:
        securityhub = libs.get_client('securityhub')
        filters = {
            'ProductFields': [{
                'Key': 'Service_Name',
                'Value': 'Reconnoitre',
                'Comparison': 'CONTAINS'
            }]
        }
        if not archived:
            filters['RecordState'] = [{
                'Value': 'ACTIVE',
                'Comparison': 'EQUALS'
            }]
        response = securityhub.get_findings(Filters=filters)
        while response:
            findings += response['Findings']
            response = securityhub.get_findings(
                Filters=filters, NextToken=response['NextToken']
            ) if 'NextToken' in response else None
        return findings

    def format_securityhub(self) -> list:
        log = logging.getLogger()
        securityhub = libs.get_client('securityhub')
        sechub_resp = self.securityhub_findings()
        active_findings = {
            item['Id']: (item['Compliance']['Status'], item['WorkflowState'])
            for item in sechub_resp
        }
        findings = []
        for finding in self.findings:
            awssh_finding = finding.toDict()
            if finding._make_id() in active_findings:
                compliance_status, workflow_state = active_findings[finding._make_id()]
                if compliance_status != finding.compliance_status:
                    if finding.compliance_status == Finding.STATUS_PASSED:
                        awssh_finding['RecordState'] = 'ARCHIVED'
                        awssh_finding['Workflow'] = 'RESOLVED'
                    elif workflow_state != 'IN_PROGRESS':
                        awssh_finding['Workflow'] = 'IN_PROGRESS'

            findings.append(awssh_finding)
        response = securityhub.batch_import_findings(Findings=findings)
        if response["FailedCount"] > 0:
            log.warn(f'AWS Security Hub findings {response["SuccessCount"]} sent and {response["FailedCount"]} failed')
            log.debug(f'AWS Security Hub failed findings {response["FailedFindings"]}')
            for failure in response["FailedFindings"]:
                for f in self.findings:
                    finding = f.toDict()
                    if finding['Id'] == failure['Id']:
                        log.debug(json.dumps(finding, indent=2))
        else:
            log.info(f'AWS Security Hub findings {response["SuccessCount"]} sent and {response["FailedCount"]} failed')
        return findings


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
    def make_finding_id(input_str: str) -> str:
        return xxh64_hexdigest(f"{input_str}", seed=20141025)

    @staticmethod
    def fix_custom_data(data: dict) -> dict:
        ret = {}
        for k, v in data.items():
            if isinstance(v, int) or isinstance(v, bool):
                ret[k] = str(v)
            elif isinstance(v, datetime):
                ret[k] = libs.to_iso8601(v)
            elif isinstance(v, dict):
                ret[k] = Reconnoitre.fix_custom_data(v)
            else:
                ret[k] = v
        return ret

    @staticmethod
    def prepare_queue(rules: list, account: list, ignore_list: list, mode: str) -> list:
        c = libs.get_config('config')
        queue = []
        # pick configured cis level rules only
        if mode == 'cis':
            rules = [
                x for x in rules
                if x.get('level') <= c['compliance'].get('cis_level', 2)
            ]

        for r in rules:
            if mode == 'custom':
                rule = CustomScan(account, r)
            elif mode == 'cis':
                rule = CISScan(account, r)
            if r.get('regions'):
                for region in r.get('regions'):
                    rule.setRegion(region)
                    queue.append(rule)
            else:
                queue.append(rule)
        return queue

    @staticmethod
    def format_text(scans: list) -> None:
        log = logging.getLogger()
        result_agg = {
            Reconnoitre.NON_COMPLIANT: 0,
            Reconnoitre.COMPLIANT: 0,
        }
        for record in scans:
            result_agg[record.result] += 1
            for finding in record.findings:
                finding_str = finding.toString()
                if finding.compliance_status == Finding.STATUS_FAILED:
                    log.error(finding_str)
                if finding.compliance_status == Finding.STATUS_WARNING:
                    log.warn(finding_str)
                if finding.compliance_status in [Finding.STATUS_NOT_AVAILABLE, Finding.STATUS_PASSED]:
                    log.info(finding_str)

        total = result_agg[Reconnoitre.NON_COMPLIANT] + result_agg[
            Reconnoitre.COMPLIANT]
        if result_agg[Reconnoitre.NON_COMPLIANT] != 0:
            log.error(
                f"Scanned {total} Rules with {result_agg[Reconnoitre.NON_COMPLIANT]} {Reconnoitre.NON_COMPLIANT} issues found"
            )
        else:
            log.info(f"{Reconnoitre.COMPLIANT} ({total} Rules)")

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
