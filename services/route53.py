from models import RuleCheckResult
import boto3


# client = boto3.client("")


def route53_query_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
