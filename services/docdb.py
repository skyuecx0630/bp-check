from models import RuleCheckResult
import boto3


# client = boto3.client("")


def docdb_cluster_audit_logging_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def docdb_cluster_backup_retention_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def docdb_cluster_deletion_protection_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def docdb_cluster_encrypted():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
