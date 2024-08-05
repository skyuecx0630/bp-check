from models import RuleCheckResult
import boto3


# client = boto3.client("")


def efs_access_point_enforce_root_directory():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def efs_access_point_enforce_user_identity():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def efs_automatic_backups_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def efs_encrypted_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def efs_mount_target_public_accessible():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
