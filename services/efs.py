from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class EFSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("efs")
        self.ec2_client = boto3.client("ec2")

    @cached_property
    def access_points(self):
        return self.client.describe_access_points()["AccessPoints"]

    @cached_property
    def file_systems(self):
        return self.client.describe_file_systems()["FileSystems"]

    def efs_access_point_enforce_root_directory(self):
        compliant_resource = []
        non_compliant_resources = []

        for access_point in self.access_points:
            if access_point["RootDirectory"]["Path"] != "/":
                compliant_resource.append(access_point["AccessPointArn"])
            else:
                non_compliant_resources.append(access_point["AccessPointArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def efs_access_point_enforce_user_identity(self):
        compliant_resource = []
        non_compliant_resources = []

        for access_point in self.access_points:
            if "PosixUser" in access_point:
                compliant_resource.append(access_point["AccessPointArn"])
            else:
                non_compliant_resources.append(access_point["AccessPointArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def efs_automatic_backups_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for file_system in self.file_systems:
            response = self.client.describe_backup_policy(
                FileSystemId=file_system["FileSystemId"]
            )

            if response["BackupPolicy"]["Status"] == "ENABLED":
                compliant_resource.append(file_system["FileSystemArn"])
            else:
                non_compliant_resources.append(file_system["FileSystemArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def efs_encrypted_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for file_system in self.file_systems:
            if file_system["Encrypted"]:
                compliant_resource.append(file_system["FileSystemArn"])
            else:
                non_compliant_resources.append(file_system["FileSystemArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def efs_mount_target_public_accessible(self):
        compliant_resource = []
        non_compliant_resources = []

        for file_system in self.file_systems:
            mount_targets = self.client.describe_mount_targets(
                FileSystemId=file_system["FileSystemId"]
            )["MountTargets"]

            for mount_target in mount_targets:
                subnet_id = mount_target["SubnetId"]
                routes = self.ec2_client.describe_route_tables(
                    Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
                )["RouteTables"][0]["Routes"]

                for route in routes:
                    if (
                        "DestinationCidrBlock" in route
                        and route["DestinationCidrBlock"] == "0.0.0.0/0"
                        and "GatewayId" in route
                        and route["GatewayId"].startswith("igw-")
                    ):
                        non_compliant_resources.append(file_system["FileSystemArn"])
                        break

        non_compliant_resources = list(set(non_compliant_resources))
        compliant_resource = list(
            set(compliant_resource) - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = EFSRuleChecker
