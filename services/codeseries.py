import boto3


build_client = boto3.client("codebuild")

deploy_client = boto3.client("codedeploy")


def codebuild_project_environment_privileged_check():
    compliant_resources = []
    non_compliant_resources = []
    projects = build_client.list_projects()["projects"]

    for project in projects:
        project = build_client.batch_get_projects(names=[project])["projects"][0]

        if project["environment"]["privilegedMode"] != True:
            compliant_resources.append(project["arn"])
        else:
            non_compliant_resources.append(project["arn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def codebuild_project_logging_enabled():
    compliant_resources = []
    non_compliant_resources = []
    projects = build_client.list_projects()["projects"]

    for project in projects:
        project = build_client.batch_get_projects(names=[project])["projects"][0]
        logs_config = project["logsConfig"]

        if logs_config["cloudWatchLogs"]["status"] == "ENABLED" or logs_config["s3Logs"]["status"] == "ENABLED":
            compliant_resources.append(project["arn"])
        else:
            non_compliant_resources.append(project["arn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def codedeploy_auto_rollback_monitor_enabled():
    compliant_resources = []
    non_compliant_resources = []
    applications = deploy_client.list_applications()["applications"]

    for application in applications:
        deployment_groups = deploy_client.list_deployment_groups(applicationName=application)["deploymentGroups"]
        for deployment_group in deployment_groups:
            deployment_group = deploy_client.get_deployment_group(
                applicationName=application, deploymentGroupName=deployment_group
            )["deploymentGroupInfo"]

            if (
                deployment_group["alarmConfiguration"]["enabled"] == True
                and deployment_group["autoRollbackConfiguration"]["enabled"] == True
            ):
                compliant_resources.append(deployment_group["deploymentGroupId"])
            else:
                non_compliant_resources.append(deployment_group["deploymentGroupId"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
