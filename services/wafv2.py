from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class WAFv2RuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("wafv2")
        self.global_client = boto3.client("wafv2", region_name="us-east-1")

    @cached_property
    def regional_web_acls(self):
        return self.client.list_web_acls(Scope="REGIONAL")["WebACLs"]

    @cached_property
    def cloudfront_web_acls(self):
        return self.global_client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]

    @cached_property
    def regional_rule_groups(self):
        rule_groups = self.client.list_rule_groups(Scope="REGIONAL")["RuleGroups"]
        return [
            self.client.get_rule_group(ARN=rule_group["ARN"])["RuleGroup"]
            for rule_group in rule_groups
        ]

    @cached_property
    def cloudfront_rule_groups(self):
        rule_groups = self.global_client.list_rule_groups(Scope="CLOUDFRONT")[
            "RuleGroups"
        ]
        return [
            self.global_client.get_rule_group(ARN=rule_group["ARN"])["RuleGroup"]
            for rule_group in rule_groups
        ]

    def wafv2_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for web_acl in self.regional_web_acls:
            try:
                configuration = self.client.get_logging_configuration(
                    ResourceArn=web_acl["ARN"]
                )
                compliant_resources.append(web_acl["ARN"])
            except Exception as e:
                if e.__class__.__name__ == "WAFNonexistentItemException":
                    non_compliant_resources.append(web_acl["ARN"])
                else:
                    raise e

        for web_acl in self.cloudfront_web_acls:
            try:
                configuration = self.global_client.get_logging_configuration(
                    ResourceArn=web_acl["ARN"]
                )
                compliant_resources.append(web_acl["ARN"])
            except Exception as e:
                if e.__class__.__name__ == "WAFNonexistentItemException":
                    non_compliant_resources.append(web_acl["ARN"])
                else:
                    raise e

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def wafv2_rulegroup_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for rule_group in self.regional_rule_groups:
            if rule_group["VisibilityConfig"]["CloudWatchMetricsEnabled"] == True:
                compliant_resources.append(rule_group["ARN"])
            else:
                non_compliant_resources.append(rule_group["ARN"])

        for rule_group in self.cloudfront_rule_groups:
            if rule_group["VisibilityConfig"]["CloudWatchMetricsEnabled"] == True:
                compliant_resources.append(rule_group["ARN"])
            else:
                non_compliant_resources.append(rule_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def wafv2_rulegroup_not_empty(self):
        compliant_resources = []
        non_compliant_resources = []

        for rule_group in self.regional_rule_groups:
            if len(rule_group["Rules"]) > 0:
                compliant_resources.append(rule_group["ARN"])
            else:
                non_compliant_resources.append(rule_group["ARN"])

        for rule_group in self.cloudfront_rule_groups:
            if len(rule_group["Rules"]) > 0:
                compliant_resources.append(rule_group["ARN"])
            else:
                non_compliant_resources.append(rule_group["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def wafv2_webacl_not_empty(self):
        compliant_resources = []
        non_compliant_resources = []

        for web_acl in self.regional_web_acls:
            response = self.client.get_web_acl(
                Id=web_acl["Id"], Name=web_acl["Name"], Scope="REGIONAL"
            )
            if len(response["WebACL"]["Rules"]) > 0:
                compliant_resources.append(web_acl["ARN"])
            else:
                non_compliant_resources.append(web_acl["ARN"])

        for web_acl in self.cloudfront_web_acls:
            response = self.global_client.get_web_acl(
                Id=web_acl["Id"], Name=web_acl["Name"], Scope="CLOUDFRONT"
            )
            if len(response["WebACL"]["Rules"]) > 0:
                compliant_resources.append(web_acl["ARN"])
            else:
                non_compliant_resources.append(web_acl["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = WAFv2RuleChecker
