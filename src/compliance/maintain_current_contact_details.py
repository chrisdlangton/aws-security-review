import libs
import time
import pytz
from datetime import datetime
from compliance import Reconnoitre, BaseScan


def maintain_current_contact_details(rule: BaseScan):
    rule.setResult(Reconnoitre.NOT_APPLICABLE)
    return rule
