from models import RuleCheckResult
import boto3


# client = boto3.client("")


def wafv2_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def wafv2_rulegroup_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def wafv2_rulegroup_not_empty():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def wafv2_webacl_not_empty():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
