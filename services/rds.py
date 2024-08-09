from models import RuleCheckResult
import datetime
from dateutil.tz import tzlocal
import boto3

client = boto3.client("rds")
backup_client = boto3.client("backup")
ec2_client = boto3.client("ec2")


def aurora_last_backup_recovery_point_created():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        recovery_points = backup_client.list_recovery_points_by_resource(ResourceArn=cluster["DBClusterArn"])[
            "RecoveryPoints"
        ]
        recovery_point_creation_dates = sorted([i["CreationDate"] for i in recovery_points])
        if datetime.datetime.now(tz=tzlocal()) - recovery_point_creation_dates[-1] < datetime.timedelta(days=1):
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def aurora_mysql_backtracking_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster["Engine"] == "aurora-mysql" and cluster.get("EarliestBacktrackTime", None) == None:
            non_compliant_resources.append(cluster["DBClusterArn"])
        else:
            compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def db_instance_backup_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("BackupRetentionPeriod", None) != None:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_auto_minor_version_upgrade_enable():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("AutoMinorVersionUpgrade", None) == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_default_admin_check():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("MasterUsername", None) not in ["admin", "postgres"]:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_deletion_protection_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("DeletionProtection", None) == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_encrypted_at_rest():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("StorageEncrypted", None) == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_iam_authentication_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if cluster.get("IAMDatabaseAuthenticationEnabled", None) == True:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_cluster_multi_az_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if len(cluster.get("AvailabilityZones", [])) > 1:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_db_security_group_not_allowed():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    security_groups = ec2_client.describe_security_groups()["SecurityGroups"]
    default_security_group_ids = [i["GroupId"] for i in security_groups if i["GroupName"] == "default"]

    for cluster in clusters:
        db_security_groups = [i["VpcSecurityGroupId"] for i in cluster["VpcSecurityGroups"] if i["Status"] == "active"]

        for default_security_group_id in default_security_group_ids:
            if default_security_group_id in db_security_groups:
                non_compliant_resources.append(cluster["DBClusterArn"])
                break
        else:
            compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_enhanced_monitoring_enabled():
    compliant_resources = []
    non_compliant_resources = []
    instances = client.describe_db_instances()["DBInstances"]

    for instance in instances:
        if instance.get("MonitoringInterval", 0) != 0:
            compliant_resources.append(instance["DBInstanceArn"])
        else:
            non_compliant_resources.append(instance["DBInstanceArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_instance_deletion_protection_enabled():
    compliant_resources = []
    non_compliant_resources = []
    instances = client.describe_db_instances()["DBInstances"]

    for instance in instances:
        if instance.get("DeletionProtection", False) != False:
            compliant_resources.append(instance["DBInstanceArn"])
        else:
            non_compliant_resources.append(instance["DBInstanceArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_instance_public_access_check():
    compliant_resources = []
    non_compliant_resources = []
    instances = client.describe_db_instances()["DBInstances"]

    for instance in instances:
        if instance.get("PubliclyAccessible") == False:
            compliant_resources.append(instance["DBInstanceArn"])
        else:
            non_compliant_resources.append(instance["DBInstanceArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    clusters = client.describe_db_clusters()["DBClusters"]

    for cluster in clusters:
        if sorted(cluster["EnabledCloudwatchLogsExports"]) == ["audit", "error", "general", "slowquery"]:
            compliant_resources.append(cluster["DBClusterArn"])
        else:
            non_compliant_resources.append(cluster["DBClusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def rds_snapshot_encrypted():
    compliant_resources = []
    non_compliant_resources = []

    cluster_snapshots = client.describe_db_cluster_snapshots()["DBClusterSnapshots"]

    for snapshot in cluster_snapshots:
        if snapshot.get("StorageEncrypted") == True:
            compliant_resources.append(snapshot["DBClusterSnapshotArn"])
        else:
            non_compliant_resources.append(snapshot["DBClusterSnapshotArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
