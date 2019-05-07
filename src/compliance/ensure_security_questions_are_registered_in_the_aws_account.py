import libs
import time
import pytz
from datetime import datetime
from compliance import Reconnoitre, BaseScan


def ensure_security_questions_are_registered_in_the_aws_account(rule: BaseScan):
    rule.setResult(Reconnoitre.NOT_APPLICABLE)
    return rule
