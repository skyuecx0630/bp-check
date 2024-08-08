from models import RuleCheckResult
import boto3
import json


client = boto3.client("lambda")
iam_client = boto3.client("iam")


def lambda_dlq_check():
    compliant_resource = []
    non_compliant_resources = []
    functions = client.list_functions()["Functions"]

    for function in functions:
        if "DeadLetterConfig" in function:
            compliant_resource.append(function["FunctionArn"])
        else:
            non_compliant_resources.append(function["FunctionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def lambda_function_public_access_prohibited():
    compliant_resource = []
    non_compliant_resources = []
    functions = client.list_functions()["Functions"]

    for function in functions:
        try:
            policy = json.loads(client.get_policy(FunctionName=function["FunctionName"])["Policy"])
            for statement in policy["Statement"]:
                if statement["Principal"] in ["*", "", '{"AWS": ""}', '{"AWS": "*"}']:
                    non_compliant_resources.append(function["FunctionArn"])
                    break
            else:
                compliant_resource.append(function["FunctionArn"])
        except Exception as e:
            if e.__class__.__name__ == "ResourceNotFoundException":
                non_compliant_resources.append(function["FunctionArn"])
            else:
                raise e

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def lambda_function_settings_check():
    compliant_resource = []
    non_compliant_resources = []
    functions = client.list_functions()["Functions"]

    default_timeout = 3
    default_memory_size = 128

    for function in functions:
        if function["Timeout"] == default_timeout or function["MemorySize"] == default_memory_size:
            non_compliant_resources.append(function["FunctionArn"])
        else:
            compliant_resource.append(function["FunctionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def lambda_inside_vpc():
    compliant_resource = []
    non_compliant_resources = []
    functions = client.list_functions()["Functions"]

    for function in functions:
        if "VpcConfig" in function:
            compliant_resource.append(function["FunctionArn"])
        else:
            non_compliant_resources.append(function["FunctionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
