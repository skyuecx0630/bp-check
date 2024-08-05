from pydantic import BaseModel


class RuleCheckResult(BaseModel):
    passed: bool
    compliant_resources: list[str]
    non_compliant_resources: list[str]
