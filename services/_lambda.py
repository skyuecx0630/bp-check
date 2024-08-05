from models import RuleCheckResult
import boto3


# client = boto3.client("")


def lambda_dlq_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def lambda_function_public_access_prohibited():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def lambda_function_settings_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def lambda_inside_vpc():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
