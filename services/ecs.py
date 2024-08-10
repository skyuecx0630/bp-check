from models import RuleCheckResult
import boto3


client = boto3.client("ecs")


def ecs_awsvpc_networking_enabled():
    compliant_resources = []
    non_compliant_resources = []
    task_definitions = client.list_task_definitions(status="ACTIVE")["taskDefinitionArns"]
    latest_task_definitions = {}

    for task_definition in task_definitions:
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
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
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("privileged") == True:
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
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("readonlyRootFilesystem") == False:
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
    cluster_arns = client.list_clusters()["clusterArns"]

    for cluster_arn in cluster_arns:
        clusters = client.describe_clusters(clusters=[cluster_arn], include=["SETTINGS"])["clusters"]

        for cluster in clusters:
            settings = cluster["settings"]

            for setting in settings:
                if setting["name"] == "containerInsights" and setting["value"] == "enabled":
                    compliant_resources.append(cluster_arn)
                    break
            else:
                non_compliant_resources.append(cluster_arn)

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
        services = client.list_services(cluster=cluster_arn, launchType="FARGATE")["serviceArns"]

        for service in services:
            service = client.describe_services(cluster=cluster_arn, services=[service])["services"][0]

            if service["launchType"] == "FARGATE":
                if service["platformVersion"] == "LATEST":
                    compliant_resources.append(service["serviceArn"])
                else:
                    non_compliant_resources.append(service["serviceArn"])
            else:
                compliant_resources.append(service["serviceArn"])

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
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("logConfiguration") == None:
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
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
        task_definition = client.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
        containers = task_definition["containerDefinitions"]

        for container in containers:
            if container.get("memory") == None:
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
        if latest_task_definitions.get(task_definition.rsplit(":", 1)[0], 0) < int(task_definition.rsplit(":", 1)[1]):
            latest_task_definitions[task_definition.rsplit(":", 1)[0]] = int(task_definition.rsplit(":", 1)[1])

    for task_definition in latest_task_definitions.keys():
        task_definition_arn = f"{task_definition}:{latest_task_definitions[task_definition]}"
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
