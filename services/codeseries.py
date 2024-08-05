from models import RuleCheckResult
import boto3


# client = boto3.client("")


def codebuild_project_environment_privileged_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def codebuild_project_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def codedeploy_auto_rollback_monitor_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
