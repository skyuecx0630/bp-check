from models import RuleCheckResult, RuleChecker
import boto3


class SecurityHubRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("securityhub")
        self.sts_client = boto3.client("sts")

    def securityhub_enabled(self):
        compliant_resources = []
        non_compliant_resources = []
        aws_account_id = self.sts_client.get_caller_identity()["Account"]

        try:
            hub = self.client.describe_hub()
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


rule_checker = SecurityHubRuleChecker
