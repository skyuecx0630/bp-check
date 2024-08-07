from models import RuleCheckResult
import boto3


v2_client = boto3.client('apigatewayv2')
v1_client = boto3.client('apigateway')
wafv2_client = boto3.client('wafv2')

def api_gwv2_access_logs_enabled():
    apis = v2_client.get_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'Items' in apis:
        for api in apis['Items']:
            stages = v2_client.get_stages(
                ApiId=api['ApiId'],
            )
            if 'Items' not in stages: continue
            noncompliant_stage_names = [
                stage['StageName']
                for stage in stages['Items']
                if 'AccessLogSettings' not in stage
            ]
            if noncompliant_stage_names:
                identity = api['Name'] + " | " + ", ".join(noncompliant_stage_names)
                non_compliant_resources.append(identity)
            else:
                compliant_resources.append(api['name'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )


def api_gwv2_authorization_type_configured():
    apis = v2_client.get_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'Items' in apis:
        for api in apis['Items']:
            response = v2_client.get_routes(
                ApiId=api['ApiId'],
            )
            noncomplaint_routes = [
                route['RouteKey']
                for route in response['Items']
                if route['AuthorizationType'] == "NONE"
            ]
            if noncomplaint_routes:
                identity = api['Name'] + " | " + ', '.join(noncomplaint_routes)
                non_compliant_resources.append(identity)
            else:
                compliant_resources.append(api['Name'])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )


def api_gw_associated_with_waf():
    apis = v1_client.get_rest_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'items' in apis:
        for api in apis['items']:
            stages = v1_client.get_stages(
                restApiId=api['id'],
            )
            if 'item' in stages:
                for stage in stages['item']:
                    stage_arn = f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    response = wafv2_client.get_web_acl_for_resource(
                        ResourceArn=stage_arn
                    )
                    if 'WebACL' in response: compliant_resources.append(stage_arn)
                    else: non_compliant_resources.append(stage_arn)
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )


def api_gw_cache_enabled_and_encrypted():
    apis = v1_client.get_rest_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'items' in apis:
        for api in apis['items']:
            stages = v1_client.get_stages(
                restApiId=api['id'],
            )
            if 'item' in stages:
                non_compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    if not stage['methodSettings']
                ])
                non_compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    for _,settings in stage['methodSettings'].items()
                    if not settings['cachingEnabled']
                    or not settings['cacheDataEncrypted']
                ])
                compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    for _,settings in stage['methodSettings'].items()
                    if settings['cachingEnabled']
                    and settings['cacheDataEncrypted']
                ])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )


def api_gw_execution_logging_enabled():
    apis = v1_client.get_rest_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'items' in apis:
        for api in apis['items']:
            stages = v1_client.get_stages(
                restApiId=api['id'],
            )
            if 'item' in stages:
                non_compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    if not stage['methodSettings']
                ])
                non_compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    for _,settings in stage['methodSettings'].items()
                    if not (settings['loggingLevel'] == "INFO"
                            or settings['loggingLevel'] == "ERROR")
                ])
                compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    for _,settings in stage['methodSettings'].items()
                    if settings['loggingLevel'] == "INFO"
                    or settings['loggingLevel'] == "ERROR"
                ])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )


def api_gw_xray_enabled():
    apis = v1_client.get_rest_apis()
    compliant_resources=[]
    non_compliant_resources=[]
    if 'items' in apis:
        for api in apis['items']:
            stages = v1_client.get_stages(
                restApiId=api['id'],
            )
            if 'item' in stages:
                non_compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    if not stage['tracingEnabled']
                ])
                compliant_resources.extend([
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages['item']
                    if stage['tracingEnabled']
                ])
    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources
    )
