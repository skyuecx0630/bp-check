from models import RuleCheckResult
import boto3


# client = boto3.client("")


def cw_loggroup_retention_period_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudwatch_alarm_settings_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
