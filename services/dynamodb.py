from models import RuleCheckResult
import datetime
import boto3


client = boto3.client("dynamodb")
autoscaling_client = boto3.client("application-autoscaling")


def dynamodb_autoscaling_enabled():
    compliant_resources = []
    non_compliant_resources = []
    table_names = client.list_tables()["TableNames"]

    for table_name in table_names:
        table = client.describe_table(TableName=table_name)["Table"]

        if table.get("BillingModeSummary", {}).get("BillingMode") == "PAY_PER_REQUEST":
            compliant_resources.append(table["TableArn"])
            continue

        scaling_policies = autoscaling_client.describe_scaling_policies(
            ServiceNamespace="dynamodb", ResourceId=f"table/{table_name}"
        )["ScalingPolicies"]
        scaling_policy_dimensions = [i["ScalableDimension"] for i in scaling_policies]
        if (
            "dynamodb:table:ReadCapacityUnits" in scaling_policy_dimensions
            and "dynamodb:table:WriteCapacityUnits" in scaling_policy_dimensions
        ):
            compliant_resources.append(table["TableArn"])
        else:
            non_compliant_resources.append(table["TableArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def dynamodb_last_backup_recovery_point_created():
    compliant_resources = []
    non_compliant_resources = []

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def dynamodb_pitr_enabled():
    compliant_resources = []
    non_compliant_resources = []
    table_names = client.list_tables()["TableNames"]

    for table_name in table_names:
        backup = client.describe_continuous_backups(TableName=table_name)["ContinuousBackupsDescription"]
        table = client.describe_table(TableName=table_name)["Table"]

        if backup["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "ENABLED":
            compliant_resources.append(table["TableArn"])
        else:
            non_compliant_resources.append(table["TableArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def dynamodb_table_deletion_protection_enabled():
    compliant_resources = []
    non_compliant_resources = []
    table_names = client.list_tables()["TableNames"]

    for table_name in table_names:
        table = client.describe_table(TableName=table_name)["Table"]

        if table["DeletionProtectionEnabled"] == True:
            compliant_resources.append(table["TableArn"])
        else:
            non_compliant_resources.append(table["TableArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def dynamodb_table_encrypted_kms():
    compliant_resources = []
    non_compliant_resources = []
    table_names = client.list_tables()["TableNames"]

    for table_name in table_names:
        table = client.describe_table(TableName=table_name)["Table"]

        if (
            "SSEDescription" in table
            and table["SSEDescription"]["Status"] == "ENABLED"
            and table["SSEDescription"]["SSEType"] == "KMS"
        ):
            compliant_resources.append(table["TableArn"])
        else:
            non_compliant_resources.append(table["TableArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def dynamodb_table_encryption_enabled():
    compliant_resources = []
    non_compliant_resources = []
    table_names = client.list_tables()["TableNames"]

    for table_name in table_names:
        table = client.describe_table(TableName=table_name)["Table"]

        if "SSEDescription" in table and table["SSEDescription"]["Status"] == "ENABLED":
            compliant_resources.append(table["TableArn"])
        else:
            non_compliant_resources.append(table["TableArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
