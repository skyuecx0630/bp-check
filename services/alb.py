from models import RuleCheckResult
import boto3


# client = boto3.client("")


def alb_http_drop_invalid_header_enabled():
    return RuleCheckResult(
        passed=False,
        compliant_resources=[],
        non_compliant_resources=[],
    )


def alb_waf_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elb_cross_zone_load_balancing_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elb_deletion_protection_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elb_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
