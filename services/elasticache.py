from models import RuleCheckResult
import boto3


# client = boto3.client("")


def elasticache_auto_minor_version_upgrade_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elasticache_redis_cluster_automatic_backup_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elasticache_repl_grp_auto_failover_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elasticache_repl_grp_encrypted_at_rest():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elasticache_repl_grp_encrypted_in_transit():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def elasticache_subnet_group_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
