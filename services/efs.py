from models import RuleCheckResult
import boto3


client = boto3.client("efs")
ec2_client = boto3.client("ec2")


def efs_access_point_enforce_root_directory():
    access_points = client.describe_access_points()["AccessPoints"]
    compliant_resource = []
    non_compliant_resources = []

    for access_point in access_points:
        if access_point["RootDirectory"]["Path"] != "/":
            compliant_resource.append(access_point["AccessPointArn"])
        else:
            non_compliant_resources.append(access_point["AccessPointArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def efs_access_point_enforce_user_identity():
    access_points = client.describe_access_points()["AccessPoints"]
    compliant_resource = []
    non_compliant_resources = []

    for access_point in access_points:
        if "PosixUser" in access_point:
            compliant_resource.append(access_point["AccessPointArn"])
        else:
            non_compliant_resources.append(access_point["AccessPointArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def efs_automatic_backups_enabled():
    file_systems = client.describe_file_systems()["FileSystems"]
    compliant_resource = []
    non_compliant_resources = []

    for file_system in file_systems:
        response = client.describe_backup_policy(
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


def efs_encrypted_check():
    file_systems = client.describe_file_systems()["FileSystems"]
    compliant_resource = []
    non_compliant_resources = []

    for file_system in file_systems:
        if file_system["Encrypted"] == True:
            compliant_resource.append(file_system["FileSystemArn"])
        else:
            non_compliant_resources.append(file_system["FileSystemArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def efs_mount_target_public_accessible():
    file_systems = client.describe_file_systems()["FileSystems"]
    compliant_resource = []
    non_compliant_resources = []

    for file_system in file_systems:
        mount_targets = client.describe_mount_targets(
            FileSystemId=file_system["FileSystemId"]
        )["MountTargets"]
        for mount_target in mount_targets:
            subnet_id = mount_target["SubnetId"]
            routes = ec2_client.describe_route_tables(
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
            else:
                compliant_resource.append(file_system["FileSystemArn"])

    compliant_resource = list(set(compliant_resource))
    non_compliant_resources = list(set(non_compliant_resources))

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
