from models import RuleCheckResult
import boto3


# client = boto3.client("")


def secretsmanager_rotation_enabled_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def secretsmanager_scheduled_rotation_success_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def secretsmanager_secret_periodic_rotation():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
