from models import RuleCheckResult
import boto3


v1_client = boto3.client("apigateway")
v2_client = boto3.client("apigatewayv2")


def api_gwv2_access_logs_enabled():
    apis = v2_client.get_apis()
    compliant_resources = []
    non_compliant_resources = []

    for api in apis["Items"]:
        stages = v2_client.get_stages(
            ApiId=api["ApiId"],
        )

        non_compliant_resources += [
            f"{api['Name']} / {stage['StageName']}"
            for stage in stages["Items"]
            if "AccessLogSettings" not in stage
        ]

        compliant_resources += list(
            set([f"{api['Name']} / {stage['StageName']}" for stage in stages["Items"]])
            - set(non_compliant_resources)
        )

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def api_gwv2_authorization_type_configured():
    apis = v2_client.get_apis()
    compliant_resources = []
    non_compliant_resources = []

    for api in apis["Items"]:
        response = v2_client.get_routes(
            ApiId=api["ApiId"],
        )

        non_compliant_resources += [
            f"{api['Name']} / {route['RouteKey']}"
            for route in response["Items"]
            if route["AuthorizationType"] == "NONE"
        ]

        compliant_resources += list(
            set([f"{api['Name']} / {route['RouteKey']}" for route in response["Items"]])
            - set(non_compliant_resources)
        )

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def api_gw_associated_with_waf():
    apis = v1_client.get_rest_apis()
    compliant_resources = []
    non_compliant_resources = []

    for api in apis["items"]:
        stages = v1_client.get_stages(
            restApiId=api["id"],
        )

        for stage in stages["item"]:
            stage_arn = f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"

            if "webAclArn" in stage:
                compliant_resources.append(stage_arn)
            else:
                non_compliant_resources.append(stage_arn)

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def api_gw_cache_enabled_and_encrypted():
    apis = v1_client.get_rest_apis()
    compliant_resources = []
    non_compliant_resources = []

    for api in apis["items"]:
        stages = v1_client.get_stages(
            restApiId=api["id"],
        )

        non_compliant_resources += [
            f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
            for stage in stages["item"]
            if not "*/*" in stage["methodSettings"]
            or (
                not stage["methodSettings"]["*/*"]["cachingEnabled"]
                or not stage["methodSettings"]["*/*"]["cacheDataEncrypted"]
            )
        ]
        compliant_resources += list(
            set(
                [
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages["item"]
                ]
            )
            - set(non_compliant_resources)
        )

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def api_gw_execution_logging_enabled():
    apis = v1_client.get_rest_apis()
    compliant_resources = []
    non_compliant_resources = []
    for api in apis["items"]:
        stages = v1_client.get_stages(
            restApiId=api["id"],
        )

        non_compliant_resources += [
            f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
            for stage in stages["item"]
            if not "*/*" in stage["methodSettings"]
            or (
                not "loggingLevel" in stage["methodSettings"]["*/*"]
                or stage["methodSettings"]["*/*"]["loggingLevel"] == "OFF"
            )
        ]
        compliant_resources += list(
            set(
                [
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages["item"]
                ]
            )
            - set(non_compliant_resources)
        )

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def api_gw_xray_enabled():
    apis = v1_client.get_rest_apis()
    compliant_resources = []
    non_compliant_resources = []
    for api in apis["items"]:
        stages = v1_client.get_stages(
            restApiId=api["id"],
        )

        non_compliant_resources += [
            f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
            for stage in stages["item"]
            if not stage["tracingEnabled"]
        ]
        compliant_resources += list(
            set(
                [
                    f"arn:aws:apigateway:{v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                    for stage in stages["item"]
                ]
            )
            - set(non_compliant_resources)
        )

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
