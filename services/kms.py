from models import RuleCheckResult
import boto3


# client = boto3.client("")


def cmk_backing_key_rotation_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
