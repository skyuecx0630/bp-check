from pydantic import BaseModel
from typing import List


class RuleCheckResult(BaseModel):
    passed: bool
    compliant_resources: List[str]
    non_compliant_resources: List[str]
