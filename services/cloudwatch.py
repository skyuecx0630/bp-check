from models import RuleCheckResult
import boto3


client = boto3.client("cloudwatch")
logs_client = boto3.client("logs")


def cw_loggroup_retention_period_check():
    compliant_resources = []
    non_compliant_resources = []
    log_groups = logs_client.describe_log_groups()["logGroups"]

    for log_group in log_groups:
        if "retentionInDays" in log_group and log_group["retentionInDays"] < 365:
            non_compliant_resources.append(log_group["logGroupArn"])
        else:
            compliant_resources.append(log_group["logGroupArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def cloudwatch_alarm_settings_check():
    compliant_resources = []
    non_compliant_resources = []
    alarms = client.describe_alarms()["MetricAlarms"]
    parameters = {
        "MetricName": "",  # required
        "Threshold": None,
        "EvaluationPeriods": None,
        "Period": None,
        "ComparisonOperator": None,
        "Statistic": None,
    }

    for alarm in alarms:
        for check in [i for i in parameters.keys() if parameters[i] != None]:
            if alarm["MetricName"] != parameters["MetricName"]:
                continue

            if alarm[check] != parameters[check]:
                non_compliant_resources.append(alarm["AlarmArn"])
                break
        else:
            compliant_resources.append(alarm["AlarmArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
