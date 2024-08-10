from models import RuleCheckResult
import boto3


client = boto3.client("ecs")


def ecs_awsvpc_networking_enabled():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]

        if task_definition.get("networkMode") == "awsvpc":
            compliant_resources.append(task_definition["taskDefinitionArn"])
        else:
            non_compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_containers_nonprivileged():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("privileged"):
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
                break
        else:
            compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_containers_readonly_access():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if not container.get("readonlyRootFilesystem"):
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
                break
        else:
            compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_container_insights_enabled():
    compliant_resources = []
    non_compliant_resources = []

    clusters = client.describe_clusters(include=["SETTINGS"])["clusters"]

    for cluster in clusters:
        container_insights_setting = [setting for setting in cluster["settings"] if setting["name"] == "containerInsights"]

        if container_insights_setting and container_insights_setting[0]["value"] == "enabled":
            compliant_resources.append(cluster["clusterArn"])
        else:
            non_compliant_resources.append(cluster["clusterArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_fargate_latest_platform_version():
    compliant_resources = []
    non_compliant_resources = []
    cluster_arns = client.list_clusters()["clusterArns"]

    for cluster_arn in cluster_arns:
        service_arns = client.list_services(cluster=cluster_arn, launchType="FARGATE")["serviceArns"]
        services = client.describe_services(cluster=cluster_arn, services=service_arns)["services"]
        
        for service in services:
            if service["platformVersion"] == "LATEST":
                compliant_resources.append(service["serviceArn"])
            else:
                non_compliant_resources.append(service["serviceArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_task_definition_log_configuration():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if "logConfiguration" not in container:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
                break
        else:
            compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_task_definition_memory_hard_limit():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if "memory" not in container:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
                break
        else:
            compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def ecs_task_definition_nonroot_user():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        family, revision = task_definition.rsplit(":", 1)        
        latest_task_definitions[family] = max(latest_task_definitions.get(family, 0), int(revision))

    for family, revision in latest_task_definitions.items():
        task_definition_arn = f"{family}:{revision}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("user") in [None, "root"]:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
                break
        else:
            compliant_resources.append(task_definition["taskDefinitionArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
