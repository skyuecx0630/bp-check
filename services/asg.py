from models import RuleCheckResult
import boto3


client = boto3.client("autoscaling")


def autoscaling_group_elb_healthcheck_required():
    compliant_resources = []
    non_compliant_resources = []
    asgs = client.describe_auto_scaling_groups()["AutoScalingGroups"]

    for asg in asgs:
        if asg.get("HealthCheckType", {}) == "ELB":
            compliant_resources.append(asg["AutoScalingGroupARN"])
        else:
            non_compliant_resources.append(asg["AutoScalingGroupARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def autoscaling_multiple_az():
    compliant_resources = []
    non_compliant_resources = []
    asgs = client.describe_auto_scaling_groups()["AutoScalingGroups"]

    for asg in asgs:
        if len(asg.get("AvailabilityZones", 0)) > 1:
            compliant_resources.append(asg["AutoScalingGroupARN"])
        else:
            non_compliant_resources.append(asg["AutoScalingGroupARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
