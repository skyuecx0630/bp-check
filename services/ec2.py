from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class EC2RuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("ec2")
        self.ssm_client = boto3.client("ssm")

    @cached_property
    def instances(self):
        valid_instances = [
            instance
            for reservation in self.client.describe_instances()["Reservations"]
            for instance in reservation["Instances"]
            if instance["State"]["Name"] != "terminated"
        ]
        return valid_instances

    def ec2_ebs_encryption_by_default(self):
        compliant_resources = []
        non_compliant_resources = []

        volumes = self.client.describe_volumes()["Volumes"]
        for volume in volumes:
            if volume["Encrypted"]:
                compliant_resources.append(volume["VolumeId"])
            else:
                non_compliant_resources.append(volume["VolumeId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_imdsv2_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if instance["MetadataOptions"]["HttpTokens"] == "required":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_instance_detailed_monitoring_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if instance["Monitoring"]["State"] == "enabled":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_instance_managed_by_systems_manager(self):
        compliant_resources = []
        non_compliant_resources = []

        informations = self.ssm_client.describe_instance_information()[
            "InstanceInformationList"
        ]
        managed_instance_ids = [
            info["InstanceId"] for info in informations if info["PingStatus"]
        ]

        for instance in self.instances:
            if instance["InstanceId"] in managed_instance_ids:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_instance_profile_attached(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if "IamInstanceProfile" in instance:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_no_amazon_key_pair(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if "KeyName" in instance:
                non_compliant_resources.append(instance["InstanceId"])
            else:
                compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_stopped_instance(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if instance["State"]["Name"] != "stopped":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ec2_token_hop_limit_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for instance in self.instances:
            if instance["MetadataOptions"]["HttpPutResponseHopLimit"] < 2:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = EC2RuleChecker
