from models import RuleCheckResult
import boto3


client = boto3.client("kms")


def cmk_backing_key_rotation_enabled():
    compliant_resources = []
    non_compliant_resources = []
    keys = client.list_keys()["Keys"]

    for key in keys:
        response = client.get_key_rotation_status(KeyId=key["KeyId"])

        if response["KeyRotationEnabled"] == True:
            compliant_resources.append(response["KeyId"])
        else:
            non_compliant_resources.append(response["KeyId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
