from models import RuleCheckResult, RuleChecker
from functools import cached_property

import boto3
import json


class LambdaRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("lambda")
        self.iam_client = boto3.client("iam")

    @cached_property
    def functions(self):
        return self.client.list_functions()["Functions"]

    def lambda_dlq_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for function in self.functions:
            if "DeadLetterConfig" in function:
                compliant_resource.append(function["FunctionArn"])
            else:
                non_compliant_resources.append(function["FunctionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def lambda_function_public_access_prohibited(self):
        compliant_resource = []
        non_compliant_resources = []

        for function in self.functions:
            try:
                policy = json.loads(
                    self.client.get_policy(FunctionName=function["FunctionName"])[
                        "Policy"
                    ]
                )
                for statement in policy["Statement"]:
                    if statement["Principal"] in [
                        "*",
                        "",
                        '{"AWS": ""}',
                        '{"AWS": "*"}',
                    ]:
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

    def lambda_function_settings_check(self):
        compliant_resource = []
        non_compliant_resources = []

        default_timeout = 3
        default_memory_size = 128

        for function in self.functions:
            if (
                function["Timeout"] == default_timeout
                or function["MemorySize"] == default_memory_size
            ):
                non_compliant_resources.append(function["FunctionArn"])
            else:
                compliant_resource.append(function["FunctionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def lambda_inside_vpc(self):
        compliant_resource = []
        non_compliant_resources = []

        for function in self.functions:
            if "VpcConfig" in function:
                compliant_resource.append(function["FunctionArn"])
            else:
                non_compliant_resources.append(function["FunctionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = LambdaRuleChecker
