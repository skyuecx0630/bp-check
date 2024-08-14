from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class SNSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("sns")

    @cached_property
    def topics(self):
        topics = self.client.list_topics()["Topics"]
        return [
            self.client.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]
            for topic in topics
        ]

    def sns_encrypted_kms(self):
        compliant_resources = []
        non_compliant_resources = []

        for topic in self.topics:
            if "KmsMasterKeyId" in topic:
                compliant_resources.append(topic["TopicArn"])
            else:
                non_compliant_resources.append(topic["TopicArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def sns_topic_message_delivery_notification_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for topic in self.topics:
            notification_roles = [
                attribute
                for attribute in topic.keys()
                if attribute.endswith("FeedbackRoleArn")
            ]

            if notification_roles:
                compliant_resources.append(topic["TopicArn"])
            else:
                non_compliant_resources.append(topic["TopicArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = SNSRuleChecker
