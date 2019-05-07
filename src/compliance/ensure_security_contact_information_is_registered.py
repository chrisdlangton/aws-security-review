import libs
import time
import pytz
from datetime import datetime
from compliance import Reconnoitre, BaseScan


def ensure_security_contact_information_is_registered(rule: BaseScan):
    rule.setResult(Reconnoitre.NOT_APPLICABLE)
    return rule
