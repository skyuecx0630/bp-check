from models import RuleCheckResult, RuleChecker
import boto3


class CloudWatchRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("cloudwatch")
        self.logs_client = boto3.client("logs")

    def cw_loggroup_retention_period_check(self):
        compliant_resources = []
        non_compliant_resources = []
        log_groups = self.logs_client.describe_log_groups()["logGroups"]

        # This rule should check if `retentionInDays` is less than n days.
        # But, instead of that, this will check if the retention setting is set to "Never expire" or not
        for log_group in log_groups:
            if "retentionInDays" in log_group:
                compliant_resources.append(log_group["logGroupArn"])
            else:
                non_compliant_resources.append(log_group["logGroupArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudwatch_alarm_settings_check(self):
        compliant_resources = []
        non_compliant_resources = []
        alarms = self.client.describe_alarms()["MetricAlarms"]
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


rule_checker = CloudWatchRuleChecker
