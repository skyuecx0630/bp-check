from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class ASGRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("autoscaling")

    @cached_property
    def asgs(self):
        return self.client.describe_auto_scaling_groups()["AutoScalingGroups"]

    def autoscaling_group_elb_healthcheck_required(self):
        compliant_resources = []
        non_compliant_resources = []

        for asg in self.asgs:
            if (
                asg["LoadBalancerNames"]
                or asg["TargetGroupARNs"]
                and asg["HealthCheckType"] != "ELB"
            ):
                non_compliant_resources.append(asg["AutoScalingGroupARN"])
            else:
                compliant_resources.append(asg["AutoScalingGroupARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def autoscaling_multiple_az(self):
        compliant_resources = []
        non_compliant_resources = []

        for asg in self.asgs:
            if len(asg["AvailabilityZones"]) > 1:
                compliant_resources.append(asg["AutoScalingGroupARN"])
            else:
                non_compliant_resources.append(asg["AutoScalingGroupARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def autoscaling_launch_template(self):
        compliant_resources = []
        non_compliant_resources = []

        for asg in self.asgs:
            if "LaunchConfigurationName" in asg:
                non_compliant_resources.append(asg["AutoScalingGroupARN"])
            else:
                compliant_resources.append(asg["AutoScalingGroupARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = ASGRuleChecker
