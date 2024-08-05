from models import RuleCheckResult
import boto3


# client = boto3.client("")


def autoscaling_group_elb_healthcheck_required():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def autoscaling_multiple_az():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
