from models import RuleCheckResult
import boto3


# client = boto3.client("")


def ecs_awsvpc_networking_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_containers_nonprivileged():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_containers_readonly_access():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_container_insights_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_fargate_latest_platform_version():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_task_definition_log_configuration():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_task_definition_memory_hard_limit():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def ecs_task_definition_nonroot_user():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
