from models import RuleCheckResult
import boto3


# client = boto3.client("")


def required_tags():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
