from models import RuleCheckResult
import boto3
import datetime
from dateutil.tz import tzlocal


client = boto3.client("secretsmanager")


def secretsmanager_rotation_enabled_check():
    compliant_resources = []
    non_compliant_resources = []
    secrets = client.list_secrets()["SecretList"]

    for secret in secrets:
        if secret.get("RotationEnabled") == True:
            compliant_resources.append(secret["ARN"])
        else:
            non_compliant_resources.append(secret["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def secretsmanager_scheduled_rotation_success_check():
    compliant_resources = []
    non_compliant_resources = []
    secrets = client.list_secrets()["SecretList"]

    for secret in secrets:
        if secret.get("RotationEnabled") == True:
            if 'LastRotatedDate' not in secret:
                non_compliant_resources.append(secret["ARN"])
                continue

            now = datetime.datetime.now(tz=tzlocal())
            rotation_period = datetime.timedelta(
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


def secretsmanager_secret_periodic_rotation():
    compliant_resources = []
    non_compliant_resources = []
    secrets = client.list_secrets()["SecretList"]

    for secret in secrets:
        if secret.get("RotationEnabled") == True:
            if 'LastRotatedDate' not in secret:
                non_compliant_resources.append(secret["ARN"])
                continue

            now = datetime.datetime.now(tz=tzlocal())
            elapsed_time_after_rotation = now - secret["LastRotatedDate"]

            if elapsed_time_after_rotation > datetime.timedelta(days=90):
                non_compliant_resources.append(secret["ARN"])
            else:
                compliant_resources.append(secret["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
