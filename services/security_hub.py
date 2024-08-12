from models import RuleCheckResult
import boto3


client = boto3.client("securityhub")

sts_client = boto3.client("sts")


def securityhub_enabled():
    compliant_resources = []
    non_compliant_resources = []
    aws_account_id = sts_client.get_caller_identity()["Account"]

    try:
        hub = client.describe_hub()
        compliant_resources.append(aws_account_id)
    except Exception as e:
        if e.__class__.__name__ == "InvalidAccessException":
            non_compliant_resources.append(aws_account_id)
        else:
            raise e

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
