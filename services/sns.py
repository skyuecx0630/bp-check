from models import RuleCheckResult
import boto3


# client = boto3.client("")


def sns_encrypted_kms():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def sns_topic_message_delivery_notification_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
