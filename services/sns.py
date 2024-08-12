import boto3


client = boto3.client("sns")


def sns_encrypted_kms():
    compliant_resources = []
    non_compliant_resources = []
    topics = client.list_topics()["Topics"]

    for topic in topics:
        topic = client.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]
        if "KmsMasterKeyId" in topic:
            compliant_resources.append(topic["TopicArn"])
        else:
            non_compliant_resources.append(topic["TopicArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )


def sns_topic_message_delivery_notification_enabled():
    compliant_resources = []
    non_compliant_resources = []
    topics = client.list_topics()["Topics"]

    for topic in topics:
        topic = client.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]

        for key in topic.keys():
            if key.endswith("FeedbackRoleArn") == True:
                compliant_resources.append(topic["TopicArn"])
                break
        else:
            non_compliant_resources.append(topic["TopicArn"])

    return RuleCheckResult(
        passed=not non_compliant_resources,
        compliant_resources=compliant_resources,
        non_compliant_resources=non_compliant_resources,
    )
