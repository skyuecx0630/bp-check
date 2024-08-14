from pydantic import BaseModel
from utils import convert_snake_case
from typing import List


class RuleCheckResult(BaseModel):
    passed: bool
    compliant_resources: List[str]
    non_compliant_resources: List[str]


class RuleChecker:
    def __init__(self):
        pass

    def check_rule(self, rule_name) -> RuleCheckResult:
        check_func = getattr(self, convert_snake_case(rule_name))
        return check_func()
