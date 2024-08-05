from models import RuleCheckResult
import boto3


# client = boto3.client("")


def cloudfront_accesslogs_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudfront_associated_with_waf():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudfront_default_root_object_configured():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudfront_no_deprecated_ssl_protocols():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudfront_s3_origin_access_control_enabled():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )


def cloudfront_viewer_policy_https():
    return RuleCheckResult(
        passed=False, compliant_resources=[], non_compliant_resources=[]
    )
