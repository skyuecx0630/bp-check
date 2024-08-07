from models import RuleCheckResult
import boto3


client = boto3.client("wafv2")

cloudfront_client = boto3.client("cloudfront")


def wafv2_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    webacls = client.list_web_acls(Scope="REGIONAL")["WebACLs"]

    for webacl in webacls:
        print(webacl["ARN"])
        configuration = client.get_logging_configuration(ResourceArn=webacl["ARN"])
        if configuration["LoggingConfiguration"] != []:
            compliant_resources.append(webacl["ARN"])
        else:
            non_compliant_resources.append(webacl["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def wafv2_rulegroup_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    rule_groups = client.list_rule_groups(Scope="REGIONAL")["RuleGroups"]

    for rule_group in rule_groups:
        configuration = client.get_rule_group(ARN=rule_group["ARN"])
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
    rule_groups = client.list_rule_groups(Scope="REGIONAL")["RuleGroups"]

    for rule_group in rule_groups:
        configuration = client.get_rule_group(ARN=rule_group["ARN"])
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
    webacls = client.list_web_acls(Scope="REGIONAL")["WebACLs"]

    for webacl in webacls:
        response = client.get_web_acl(Id=webacl["Id"], Name=webacl["Name"], Scope="REGIONAL")
        if len(response["WebACL"]["Rules"]) > 0:
            compliant_resources.append(webacl["ARN"])
        else:
            non_compliant_resources.append(webacl["ARN"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
