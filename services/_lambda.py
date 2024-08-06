import botocore.errorfactory
from models import RuleCheckResult
import boto3
import botocore
import json


client = boto3.client("lambda")
iam_client = boto3.client("iam")


def lambda_dlq_check():
    compliant_resource = []
    non_compliant_resources = []
    functions = client.list_functions()["Functions"]

    for function in functions:
        response = client.get_function(FunctionName=function["FunctionName"])[
            "Configuration"
        ]
        if "DeadLetterConfig" in response:
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
            policy = json.loads(
                client.get_policy(FunctionName=function["FunctionName"])["Policy"]
            )
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

    runtime = []  # python3.7 | nodejs10.x ...

    for function in functions:
        configuration = client.get_function(FunctionName=function["FunctionName"])[
            "Configuration"
        ]

        if configuration["Runtime"] in runtime:
            compliant_resource.append(function["FunctionArn"])
        else:
            non_compliant_resources.append(function["FunctionArn"])

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
        response = client.get_function(FunctionName=function["FunctionName"])[
            "Configuration"
        ]

        if "VpcConfig" in response:
            compliant_resource.append(function["FunctionName"])
        else:
            non_compliant_resources.append(function["FunctionName"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
