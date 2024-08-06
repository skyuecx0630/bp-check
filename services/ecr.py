from models import RuleCheckResult
import boto3
import botocore


client = boto3.client("ecr")


def ecr_private_image_scanning_enabled():
    repositories = client.describe_repositories()
    compliant_resource = []
    non_compliant_resources = []

    for repository in repositories["repositories"]:
        if repository["imageScanningConfiguration"]["scanOnPush"] == True:
            compliant_resource.append(repository["repositoryArn"])
        else:
            non_compliant_resources.append(repository["repositoryArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def ecr_private_lifecycle_policy_configured():
    repositories = client.describe_repositories()
    compliant_resource = []
    non_compliant_resources = []

    for repository in repositories["repositories"]:
        try:
            response = client.get_lifecycle_policy(
                registryId=repository["registryId"],
                repositoryName=repository["repositoryName"],
            )
            compliant_resource.append(repository["repositoryArn"])
        except Exception as e:
            if e.__class__.__name__ == "LifecyclePolicyNotFoundException":
                non_compliant_resources.append(repository["repositoryArn"])
            else:
                raise e

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def ecr_private_tag_immutability_enabled():
    repositories = client.describe_repositories()
    compliant_resource = []
    non_compliant_resources = []

    for repository in repositories["repositories"]:
        if repository["imageTagMutability"] == "IMMUTABLE":
            compliant_resource.append(repository["repositoryArn"])
        else:
            non_compliant_resources.append(repository["repositoryArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def ecr_kms_encryption_1():
    repositories = client.describe_repositories()
    compliant_resource = []
    non_compliant_resources = []

    for repository in repositories["repositories"]:
        if repository["encryptionConfiguration"]["encryptionType"] == "KMS":
            compliant_resource.append(repository["repositoryArn"])
        else:
            non_compliant_resources.append(repository["repositoryArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
