from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class ElastiCacheRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("elasticache")

    @cached_property
    def clusters(self):
        return self.client.describe_cache_clusters()["CacheClusters"]

    @cached_property
    def replication_groups(self):
        return self.client.describe_replication_groups()["ReplicationGroups"]

    def elasticache_auto_minor_version_upgrade_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for cluster in self.clusters:
            if cluster["AutoMinorVersionUpgrade"]:
                compliant_resource.append(cluster["ARN"])
            else:
                non_compliant_resources.append(cluster["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elasticache_redis_cluster_automatic_backup_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for replication_group in self.replication_groups:
            if "SnapshottingClusterId" in replication_group:
                compliant_resource.append(replication_group["ARN"])
            else:
                non_compliant_resources.append(replication_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elasticache_repl_grp_auto_failover_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for replication_group in self.replication_groups:
            if replication_group["AutomaticFailover"] == "enabled":
                compliant_resource.append(replication_group["ARN"])
            else:
                non_compliant_resources.append(replication_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elasticache_repl_grp_encrypted_at_rest(self):
        compliant_resource = []
        non_compliant_resources = []

        for replication_group in self.replication_groups:
            if replication_group["AtRestEncryptionEnabled"] == True:
                compliant_resource.append(replication_group["ARN"])
            else:
                non_compliant_resources.append(replication_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elasticache_repl_grp_encrypted_in_transit(self):
        compliant_resource = []
        non_compliant_resources = []

        for replication_group in self.replication_groups:
            if replication_group["TransitEncryptionEnabled"] == True:
                compliant_resource.append(replication_group["ARN"])
            else:
                non_compliant_resources.append(replication_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elasticache_subnet_group_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for cluster in self.clusters:
            if cluster["CacheSubnetGroupName"] != "default":
                compliant_resource.append(cluster["ARN"])
            else:
                non_compliant_resources.append(cluster["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = ElastiCacheRuleChecker
