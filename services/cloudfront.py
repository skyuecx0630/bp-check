from models import RuleCheckResult
import boto3


client = boto3.client("cloudfront")


def cloudfront_accesslogs_enabled():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]["Items"]

    for distribution in distributions:
        distribution = client.get_distribution(Id=distribution["Id"])["Distribution"]
        if (
            "Logging" in distribution["DistributionConfig"]
            and distribution["DistributionConfig"]["Logging"]["Enabled"] == True
        ):
            compliant_resources.append(distribution["ARN"])
        else:
            non_compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudfront_associated_with_waf():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]["Items"]

    for distribution in distributions:
        if "WebACLId" in distribution and distribution["WebACLId"] != "":
            compliant_resources.append(distribution["ARN"])
        else:
            non_compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudfront_default_root_object_configured():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]["Items"]

    for distribution in distributions:
        distribution = client.get_distribution(Id=distribution["Id"])["Distribution"]

        if distribution["DistributionConfig"]["DefaultRootObject"] != "":
            compliant_resources.append(distribution["ARN"])
        else:
            non_compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudfront_no_deprecated_ssl_protocols():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]["Items"]

    for distribution in distributions:
        for origin in distribution["Origins"]["Items"]:
            if (
                "CustomOriginConfig" in origin
                and origin["CustomOriginConfig"]["OriginProtocolPolicy"] in ["https-only", "match-viewer"]
                and "SSLv3" in origin["CustomOriginConfig"]["OriginSslProtocols"]["Items"]
            ):

                non_compliant_resources.append(distribution["ARN"])
                break
        else:
            compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudfront_s3_origin_access_control_enabled():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]

    for distribution in distributions["Items"]:
        for origin in distribution["Origins"]["Items"]:
            if "S3OriginConfig" in origin and origin["OriginAccessControlId"] == "":
                non_compliant_resources.append(distribution["ARN"])
                break
        else:
            compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudfront_viewer_policy_https():
    compliant_resources = []
    non_compliant_resources = []
    distributions = client.list_distributions()["DistributionList"]["Items"]

    for distribution in distributions:
        if distribution["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "allow-all":
            non_compliant_resources.append(distribution["ARN"])
            continue

        allow_alls = [
            behavior
            for behavior in distribution["CacheBehaviors"]["Items"]
            if behavior["ViewerProtocolPolicy"] == "allow-all"
        ]
        if allow_alls:
            non_compliant_resources.append(distribution["ARN"])
            continue

        compliant_resources.append(distribution["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
