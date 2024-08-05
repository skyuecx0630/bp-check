from models import RuleCheckResult
import boto3


# client = boto3.client("")


def eks_cluster_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def eks_cluster_secrets_encrypted():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def eks_endpoint_no_public_access():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def eks_secrets_encrypted():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
