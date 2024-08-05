from models import RuleCheckResult
import boto3


# client = boto3.client("")


def autoscaling_launch_template():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_ebs_encryption_by_default():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_imdsv2_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_instance_detailed_monitoring_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_instance_managed_by_systems_manager():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_instance_profile_attached():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_no_amazon_key_pair():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_stopped_instance():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ec2_token_hop_limit_check():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
