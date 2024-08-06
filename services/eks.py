from models import RuleCheckResult
import boto3


client = boto3.client("eks")


def eks_cluster_logging_enabled():
    clusters = client.list_clusters()["clusters"]
    compliant_resource = []
    non_compliant_resources = []

    for cluster in clusters:
        response = client.describe_cluster(name=cluster)["cluster"]
        if (
            len(response["logging"]["clusterLogging"][0]["types"]) == 5
            and response["logging"]["clusterLogging"][0]["enabled"] == True
        ):
            compliant_resource.append(response["arn"])
        else:
            non_compliant_resources.append(response["arn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def eks_cluster_secrets_encrypted():
    clusters = client.list_clusters()["clusters"]
    compliant_resource = []
    non_compliant_resources = []

    for cluster in clusters:
        response = client.describe_cluster(name=cluster)["cluster"]
        if (
            "encryptionConfig" in response
            and "secrets" in response["encryptionConfig"][0]["resources"]
        ):
            compliant_resource.append(response["arn"])
        else:
            non_compliant_resources.append(response["arn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def eks_endpoint_no_public_access():
    clusters = client.list_clusters()["clusters"]
    compliant_resource = []
    non_compliant_resources = []

    for cluster in clusters:
        response = client.describe_cluster(name=cluster)["cluster"]
        if response["resourcesVpcConfig"]["endpointPublicAccess"] == False:
            compliant_resource.append(response["arn"])
        else:
            non_compliant_resources.append(response["arn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
