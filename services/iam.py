from models import RuleCheckResult
import boto3


# client = boto3.client("")


def iam_policy_no_statements_with_admin_access():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def iam_policy_no_statements_with_full_access():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def iam_role_managed_policy_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
