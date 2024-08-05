from models import RuleCheckResult
import boto3


# client = boto3.client("")


def ecr_private_image_scanning_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecr_private_lifecycle_policy_configured():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecr_private_tag_immutability_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecr_kms_encryption_1():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
