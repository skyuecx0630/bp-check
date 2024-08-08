from models import RuleCheckResult
import boto3


client = boto3.client("docdb")


def docdb_cluster_audit_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if "audit" in cluster["EnabledCloudwatchLogsExports"]:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def docdb_cluster_backup_retention_check():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if not cluster["BackupRetentionPeriod"] < 7:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def docdb_cluster_deletion_protection_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster["DeletionProtection"] == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def docdb_cluster_encrypted():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster["StorageEncrypted"] == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
