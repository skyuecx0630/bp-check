from models import RuleCheckResult
import boto3


client = boto3.client("elasticache")


def elasticache_auto_minor_version_upgrade_check():
    clusters = client.describe_cache_clusters()["CacheClusters"]
    compliant_resource = []
    non_compliant_resources = []

    for cluster in clusters:
        if cluster["AutoMinorVersionUpgrade"] == True:
            compliant_resource.append(cluster["ARN"])
        else:
            non_compliant_resources.append(cluster["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elasticache_redis_cluster_automatic_backup_check():
    replication_groups = client.describe_replication_groups()["ReplicationGroups"]
    compliant_resource = []
    non_compliant_resources = []

    for replication_group in replication_groups:
        if "SnapshottingClusterId" in replication_group:
            compliant_resource.append(replication_group["ARN"])
        else:
            non_compliant_resources.append(replication_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elasticache_repl_grp_auto_failover_enabled():
    replication_groups = client.describe_replication_groups()["ReplicationGroups"]
    compliant_resource = []
    non_compliant_resources = []

    for replication_group in replication_groups:
        if replication_group["AutomaticFailover"] == "enabled":
            compliant_resource.append(replication_group["ARN"])
        else:
            non_compliant_resources.append(replication_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elasticache_repl_grp_encrypted_at_rest():
    replication_groups = client.describe_replication_groups()["ReplicationGroups"]
    compliant_resource = []
    non_compliant_resources = []

    for replication_group in replication_groups:
        if replication_group["AtRestEncryptionEnabled"] == True:
            compliant_resource.append(replication_group["ARN"])
        else:
            non_compliant_resources.append(replication_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elasticache_repl_grp_encrypted_in_transit():
    replication_groups = client.describe_replication_groups()["ReplicationGroups"]
    compliant_resource = []
    non_compliant_resources = []

    for replication_group in replication_groups:
        if replication_group["TransitEncryptionEnabled"] == True:
            compliant_resource.append(replication_group["ARN"])
        else:
            non_compliant_resources.append(replication_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elasticache_subnet_group_check():
    clusters = client.describe_cache_clusters()["CacheClusters"]
    compliant_resource = []
    non_compliant_resources = []

    for cluster in clusters:
        if cluster["CacheSubnetGroupName"] != "default":
            compliant_resource.append(cluster["ARN"])
        else:
            non_compliant_resources.append(cluster["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
