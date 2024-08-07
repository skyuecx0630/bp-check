from models import RuleCheckResult
import boto3


client = boto3.client("ec2")
autoscaling_client = boto3.client("autoscaling")
ssm_client = boto3.client("ssm")


def autoscaling_launch_template():
    compliant_resources = []
    non_compliant_resources = []
    asgs = autoscaling_client.describe_auto_scaling_groups()["AutoScalingGroups"]

    for asg in asgs:
        if "LaunchConfigurationName" in asg:
            non_compliant_resources.append(asg["AutoScalingGroupARN"])
        else:
            compliant_resources.append(asg["AutoScalingGroupARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_ebs_encryption_by_default():
    compliant_resources = []
    non_compliant_resources = []
    ebses = client.describe_volumes()["Volumes"]

    for ebs in ebses:
        if ebs["Encrypted"] == True:
            compliant_resources.append(ebs["VolumeId"])
        else:
            non_compliant_resources.append(ebs["VolumeId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_imdsv2_check():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if instance["MetadataOptions"]["HttpTokens"] == "required":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_instance_detailed_monitoring_enabled():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if instance["Monitoring"]["State"] == "enabled":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_instance_managed_by_systems_manager():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]
    informations = ssm_client.describe_instance_information()["InstanceInformationList"]
    managed_instance_ids = [i["InstanceId"] for i in informations if i["PingStatus"]]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if instance["InstanceId"] in managed_instance_ids:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_instance_profile_attached():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if "IamInstanceProfile" in instance:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_no_amazon_key_pair():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if "KeyName" in instance:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_stopped_instance():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if instance["State"]["Name"] != "stopped":
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ec2_token_hop_limit_check():
    compliant_resources = []
    non_compliant_resources = []
    reservations = client.describe_instances()["Reservations"]

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            if instance["MetadataOptions"]["HttpPutResponseHopLimit"] < 2:
                compliant_resources.append(instance["InstanceId"])
            else:
                non_compliant_resources.append(instance["InstanceId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
