from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3
from datetime import datetime, timedelta
from dateutil.tz import tzlocal


class SecretsManagerRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("secretsmanager")

    @cached_property
    def secrets(self):
        return self.client.list_secrets()["SecretList"]

    def secretsmanager_rotation_enabled_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for secret in self.secrets:
            if secret.get("RotationEnabled", False):
                compliant_resources.append(secret["ARN"])
            else:
                non_compliant_resources.append(secret["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def secretsmanager_scheduled_rotation_success_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for secret in self.secrets:
            if secret.get("RotationEnabled", False):
                if "LastRotatedDate" not in secret:
                    non_compliant_resources.append(secret["ARN"])
                    continue

                now = datetime.now(tz=tzlocal())
                rotation_period = timedelta(
                    days=secret["RotationRules"]["AutomaticallyAfterDays"] + 2
                )  # 최대 2일 지연 가능 (aws)
                elapsed_time_after_rotation = now - secret["LastRotatedDate"]

                if elapsed_time_after_rotation > rotation_period:
                    non_compliant_resources.append(secret["ARN"])
                else:
                    compliant_resources.append(secret["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def secretsmanager_secret_periodic_rotation(self):
        compliant_resources = []
        non_compliant_resources = []

        for secret in self.secrets:
            if secret.get("RotationEnabled") == True:
                if "LastRotatedDate" not in secret:
                    non_compliant_resources.append(secret["ARN"])
                    continue

                now = datetime.now(tz=tzlocal())
                elapsed_time_after_rotation = now - secret["LastRotatedDate"]

                if elapsed_time_after_rotation > timedelta(days=90):
                    non_compliant_resources.append(secret["ARN"])
                else:
                    compliant_resources.append(secret["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = SecretsManagerRuleChecker
