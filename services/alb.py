from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class ALBRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("elbv2")
        self.wafv2_client = boto3.client("wafv2")

    @cached_property
    def load_balancers(self):
        return self.client.describe_load_balancers()["LoadBalancers"]

    @cached_property
    def load_balancer_attributes(self):
        responses = [
            self.client.describe_load_balancer_attributes(
                LoadBalancerArn=load_balancer["LoadBalancerArn"]
            )
            for load_balancer in self.load_balancers
        ]
        return {
            load_balancer["LoadBalancerArn"]: response
            for load_balancer, response in zip(self.load_balancers, responses)
        }

    def alb_http_drop_invalid_header_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for load_balancer in self.load_balancers:
            response = self.load_balancer_attributes[load_balancer["LoadBalancerArn"]]
            result = [
                attribute
                for attribute in filter(
                    lambda x: x["Key"]
                    == "routing.http.drop_invalid_header_fields.enabled"
                    and x["Value"] == "true",
                    response["Attributes"],
                )
            ]
            if result:
                compliant_resource.append(load_balancer["LoadBalancerArn"])
            else:
                non_compliant_resources.append(load_balancer["LoadBalancerArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def alb_waf_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for load_balancer in self.load_balancers:
            response = self.wafv2_client.get_web_acl_for_resource(
                ResourceArn=load_balancer["LoadBalancerArn"]
            )

            if "WebACL" in response:
                compliant_resource.append(load_balancer["LoadBalancerArn"])
            else:
                non_compliant_resources.append(load_balancer["LoadBalancerArn"])
        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elb_cross_zone_load_balancing_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for load_balancer in self.load_balancers:
            response = self.load_balancer_attributes[load_balancer["LoadBalancerArn"]]
            result = [
                attribute
                for attribute in filter(
                    lambda x: x["Key"] == "load_balancing.cross_zone.enabled"
                    and x["Value"] == "true",
                    response["Attributes"],
                )
            ]
            if result:
                compliant_resource.append(load_balancer["LoadBalancerArn"])
            else:
                non_compliant_resources.append(load_balancer["LoadBalancerArn"])
        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elb_deletion_protection_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for load_balancer in self.load_balancers:
            response = self.load_balancer_attributes[load_balancer["LoadBalancerArn"]]

            result = [
                attribute
                for attribute in filter(
                    lambda x: x["Key"] == "deletion_protection.enabled"
                    and x["Value"] == "true",
                    response["Attributes"],
                )
            ]
            if result:
                compliant_resource.append(load_balancer["LoadBalancerArn"])
            else:
                non_compliant_resources.append(load_balancer["LoadBalancerArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def elb_logging_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for load_balancer in self.load_balancers:
            response = self.load_balancer_attributes[load_balancer["LoadBalancerArn"]]

            result = [
                attribute
                for attribute in filter(
                    lambda x: x["Key"] == "access_logs.s3.enabled"
                    and x["Value"] == "true",
                    response["Attributes"],
                )
            ]
            if result:
                compliant_resource.append(load_balancer["LoadBalancerArn"])
            else:
                non_compliant_resources.append(load_balancer["LoadBalancerArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = ALBRuleChecker
