from models import RuleCheckResult
import boto3


client = boto3.client("elbv2")
wafv2_client = boto3.client("wafv2")

def alb_http_drop_invalid_header_enabled():
    load_balancers = client.describe_load_balancers()
    compliant_resource = []
    non_compliant_resources = []
    for load_balancer in load_balancers['LoadBalancers']:
        response = client.describe_load_balancer_attributes(
            LoadBalancerArn=load_balancer['LoadBalancerArn']
        )
        result = [
            attribute
            for attribute in filter(
                lambda x: x['Key'] == "routing.http.drop_invalid_header_fields.enabled"
                and x['Value'] == "true",
                response['Attributes'],
            )
        ]
        if result: compliant_resource.append(load_balancer['LoadBalancerArn'])
        else: non_compliant_resources.append(load_balancer['LoadBalancerArn'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def alb_waf_enabled():
    load_balancers = client.describe_load_balancers()
    compliant_resource = []
    non_compliant_resources = []
    for load_balancer in load_balancers['LoadBalancers']:
        response = wafv2_client.get_web_acl_for_resource(
            ResourceArn=load_balancer['LoadBalancerArn']
        )
        
        if 'WebACL' in response: compliant_resource.append(load_balancer['LoadBalancerArn'])
        else: non_compliant_resources.append(load_balancer['LoadBalancerArn'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elb_cross_zone_load_balancing_enabled():
    load_balancers = client.describe_load_balancers()
    compliant_resource = []
    non_compliant_resources = []
    for load_balancer in load_balancers['LoadBalancers']:
        response = client.describe_load_balancer_attributes(
            LoadBalancerArn=load_balancer['LoadBalancerArn']
        )
        result = [
            attribute
            for attribute in filter(
                lambda x: x['Key'] == "load_balancing.cross_zone.enabled"
                and x['Value'] == "true",
                response['Attributes'],
            )
        ]
        if result: compliant_resource.append(load_balancer['LoadBalancerArn'])
        else: non_compliant_resources.append(load_balancer['LoadBalancerArn'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elb_deletion_protection_enabled():
    load_balancers = client.describe_load_balancers()
    compliant_resource = []
    non_compliant_resources = []
    for load_balancer in load_balancers['LoadBalancers']:
        response = client.describe_load_balancer_attributes(
            LoadBalancerArn=load_balancer['LoadBalancerArn']
        )
        result = [
            attribute
            for attribute in filter(
                lambda x: x['Key'] == "deletion_protection.enabled"
                and x['Value'] == "true",
                response['Attributes'],
            )
        ]
        if result: compliant_resource.append(load_balancer['LoadBalancerArn'])
        else: non_compliant_resources.append(load_balancer['LoadBalancerArn'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )


def elb_logging_enabled():
    load_balancers = client.describe_load_balancers()
    compliant_resource = []
    non_compliant_resources = []
    for load_balancer in load_balancers['LoadBalancers']:
        response = client.describe_load_balancer_attributes(
            LoadBalancerArn=load_balancer['LoadBalancerArn']
        )
        result = [
            attribute
            for attribute in filter(
                lambda x: x['Key'] == "connection_logs.s3.enabled"
                and x['Value'] == "true",
                response['Attributes'],
            )
        ]
        if result: compliant_resource.append(load_balancer['LoadBalancerArn'])
        else: non_compliant_resources.append(load_balancer['LoadBalancerArn'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resource,
        non_compliant_resources=non_compliant_resources,
    )
