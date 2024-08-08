from models import RuleCheckResult
import boto3


client = boto3.client("wafv2")
global_client = boto3.client("wafv2", region_name="us-east-1")


def wafv2_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    regional_web_acls = client.list_web_acls(Scope="REGIONAL")["WebACLs"]
    cloudfront_web_acls = global_client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]

    for web_acl in regional_web_acls:
        try:
            configuration = client.get_logging_configuration(ResourceArn=web_acl["ARN"])
            compliant_resources.append(web_acl["ARN"])
        except Exception as e:
            if e.__class__.__name__ == "WAFNonexistentItemException":
                non_compliant_resources.append(web_acl["ARN"])
            else:
                raise e

    for web_acl in cloudfront_web_acls:
        try:
            configuration = global_client.get_logging_configuration(ResourceArn=web_acl["ARN"])
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


def wafv2_rulegroup_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    regional_rule_groups = client.list_rule_groups(Scope="REGIONAL")["RuleGroups"]
    cloudfront_rule_groups = global_client.list_rule_groups(Scope="CLOUDFRONT")["RuleGroups"]


    for rule_group in regional_rule_groups:
        configuration = client.get_rule_group(ARN=rule_group["ARN"])
        if configuration["RuleGroup"]["VisibilityConfig"]["CloudWatchMetricsEnabled"] == True:
            compliant_resources.append(rule_group["ARN"])
        else:
            non_compliant_resources.append(rule_group["ARN"])

    for rule_group in cloudfront_rule_groups:
        configuration = global_client.get_rule_group(ARN=rule_group["ARN"])
        if configuration["RuleGroup"]["VisibilityConfig"]["CloudWatchMetricsEnabled"] == True:
            compliant_resources.append(rule_group["ARN"])
        else:
            non_compliant_resources.append(rule_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def wafv2_rulegroup_not_empty():
    compliant_resources = []
    non_compliant_resources = []
    regional_rule_groups = client.list_rule_groups(Scope="REGIONAL")["RuleGroups"]
    cloudfront_rule_groups = global_client.list_rule_groups(Scope="CLOUDFRONT")["RuleGroups"]

    for rule_group in regional_rule_groups:
        configuration = client.get_rule_group(ARN=rule_group["ARN"])
        if len(configuration["RuleGroup"]["Rules"]) > 0:
            compliant_resources.append(rule_group["ARN"])
        else:
            non_compliant_resources.append(rule_group["ARN"])

    for rule_group in cloudfront_rule_groups:
        configuration = global_client.get_rule_group(ARN=rule_group["ARN"])
        if len(configuration["RuleGroup"]["Rules"]) > 0:
            compliant_resources.append(rule_group["ARN"])
        else:
            non_compliant_resources.append(rule_group["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def wafv2_webacl_not_empty():
    compliant_resources = []
    non_compliant_resources = []
    regional_web_acls = client.list_web_acls(Scope="REGIONAL")["WebACLs"]
    cloudfront_web_acls = global_client.list_web_acls(Scope="CLOUDFRONT")["WebACLs"]

    for web_acl in regional_web_acls:
        response = client.get_web_acl(Id=web_acl["Id"], Name=web_acl["Name"], Scope="REGIONAL")
        if len(response["WebACL"]["Rules"]) > 0:
            compliant_resources.append(web_acl["ARN"])
        else:
            non_compliant_resources.append(web_acl["ARN"])
    for web_acl in cloudfront_web_acls:
        response = global_client.get_web_acl(Id=web_acl["Id"], Name=web_acl["Name"], Scope="CLOUDFRONT")
        if len(response["WebACL"]["Rules"]) > 0:
            compliant_resources.append(web_acl["ARN"])
        else:
            non_compliant_resources.append(web_acl["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
