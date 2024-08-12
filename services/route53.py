from models import RuleCheckResult
import boto3


client = boto3.client("route53")


def route53_query_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []

    public_hosted_zones = [i for i in client.list_hosted_zones()["HostedZones"] if i["Config"]["PrivateZone"] == False]
    query_logging_configs = [i["HostedZoneId"] for i in client.list_query_logging_configs()["QueryLoggingConfigs"]]

    for hosted_zone in public_hosted_zones:
        hosted_zone_id = hosted_zone["Id"].split("/")[-1]

        if hosted_zone_id in query_logging_configs:
            compliant_resources.append(hosted_zone["Name"])
        else:
            non_compliant_resources.append(hosted_zone["Name"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
