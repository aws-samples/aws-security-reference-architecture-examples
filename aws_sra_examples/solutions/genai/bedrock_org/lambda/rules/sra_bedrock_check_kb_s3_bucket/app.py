"""Config rule to check knowledge base S3 bucket configuration for Bedrock environments.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
import logging
import os
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Get AWS region from environment variable
AWS_REGION = os.environ.get("AWS_REGION")

# Initialize AWS clients
bedrock_agent_client = boto3.client("bedrock-agent", region_name=AWS_REGION)
s3_client = boto3.client("s3", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)


def check_retention(bucket_name: str) -> bool:
    """Check if bucket has retention configuration.

    Args:
        bucket_name (str): Name of the S3 bucket to check

    Returns:
        bool: True if bucket has retention configuration, False otherwise
    """
    try:
        lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return any(rule.get("Expiration") for rule in lifecycle.get("Rules", []))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
            return False
        if e.response["Error"]["Code"] != "NoSuchBucket":
            LOGGER.error(f"Error checking retention for bucket {bucket_name}: {str(e)}")
        return False


def check_encryption(bucket_name: str) -> bool:
    """Check if bucket has encryption configuration.

    Args:
        bucket_name (str): Name of the S3 bucket to check

    Returns:
        bool: True if bucket has encryption configuration, False otherwise
    """
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        return bool(encryption.get("ServerSideEncryptionConfiguration"))
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            return False
        return False


def check_access_logging(bucket_name: str) -> bool:
    """Check if bucket has access logging enabled.

    Args:
        bucket_name (str): Name of the S3 bucket to check

    Returns:
        bool: True if bucket has access logging enabled, False otherwise
    """
    try:
        logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
        return bool(logging_config.get("LoggingEnabled"))
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            return False
        return False


def check_object_locking(bucket_name: str) -> bool:
    """Check if bucket has object locking enabled.

    Args:
        bucket_name (str): Name of the S3 bucket to check

    Returns:
        bool: True if bucket has object locking enabled, False otherwise
    """
    try:
        lock_config = s3_client.get_object_lock_configuration(Bucket=bucket_name)
        return bool(lock_config.get("ObjectLockConfiguration"))
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            return False
        return False


def check_versioning(bucket_name: str) -> bool:
    """Check if bucket has versioning enabled.

    Args:
        bucket_name (str): Name of the S3 bucket to check

    Returns:
        bool: True if bucket has versioning enabled, False otherwise
    """
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return versioning.get("Status") == "Enabled"
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            return False
        return False


def check_bucket_configuration(bucket_name: str, rule_parameters: dict) -> list[str]:
    """Check S3 bucket configuration against required settings.

    Args:
        bucket_name (str): Name of the S3 bucket
        rule_parameters (dict): Rule parameters containing check flags

    Returns:
        list[str]: List of missing configurations
    """
    issues = []

    if rule_parameters.get("check_retention", "true").lower() == "true" and not check_retention(bucket_name):
        issues.append("retention")
    if rule_parameters.get("check_encryption", "true").lower() == "true" and not check_encryption(bucket_name):
        issues.append("encryption")
    if rule_parameters.get("check_access_logging", "true").lower() == "true" and not check_access_logging(bucket_name):
        issues.append("access logging")
    if rule_parameters.get("check_object_locking", "true").lower() == "true" and not check_object_locking(bucket_name):
        issues.append("object locking")
    if rule_parameters.get("check_versioning", "true").lower() == "true" and not check_versioning(bucket_name):
        issues.append("versioning")

    return issues


def get_bucket_name_from_data_source(data_source: Any) -> str | None:
    """Extract bucket name from data source configuration.

    Args:
        data_source (Dict[str, Any]): Data source configuration

    Returns:
        str | None: Bucket name if found, None otherwise
    """
    try:
        if (
            "dataSource" in data_source
            and "dataSourceConfiguration" in data_source["dataSource"]
            and "s3Configuration" in data_source["dataSource"]["dataSourceConfiguration"]
        ):
            s3_config = data_source["dataSource"]["dataSourceConfiguration"]["s3Configuration"]
            bucket_arn = s3_config.get("bucketArn", "")

            if not bucket_arn:
                return None

            bucket_name = bucket_arn.split(":")[-1]
            return bucket_name.split("/")[0] if "/" in bucket_name else bucket_name
    except Exception as e:
        LOGGER.error(f"Error processing data source: {str(e)}")
    return None


def check_knowledge_base(kb_id: str, rule_parameters: dict) -> list[str]:
    """Check a knowledge base's data sources for S3 bucket compliance.

    Args:
        kb_id (str): Knowledge base ID
        rule_parameters (dict): Rule parameters containing check flags

    Returns:
        list[str]: List of non-compliant bucket messages
    """
    non_compliant_buckets = []
    data_sources_paginator = bedrock_agent_client.get_paginator("list_data_sources")

    for ds_page in data_sources_paginator.paginate(knowledgeBaseId=kb_id):
        for ds in ds_page.get("dataSourceSummaries", []):
            data_source = bedrock_agent_client.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds["dataSourceId"])

            bucket_name = get_bucket_name_from_data_source(data_source)
            if not bucket_name:
                continue

            issues = check_bucket_configuration(bucket_name, rule_parameters)
            if issues:
                non_compliant_buckets.append(f"{bucket_name} (missing: {', '.join(issues)})")

    return non_compliant_buckets


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:
    """Evaluate if Bedrock Knowledge Base S3 bucket has required configurations.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance status and annotation
    """
    try:
        non_compliant_buckets = []
        paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")

        for page in paginator.paginate():
            for kb in page["knowledgeBaseSummaries"]:
                non_compliant_buckets.extend(check_knowledge_base(kb["knowledgeBaseId"], rule_parameters))

        if non_compliant_buckets:
            # Create a shorter message for each bucket by using abbreviations
            bucket_msgs = []
            for bucket in non_compliant_buckets:
                # Replace longer descriptions with abbreviations
                short_msg = bucket.replace("missing: ", "")
                short_msg = short_msg.replace("retention", "ret")
                short_msg = short_msg.replace("encryption", "enc")
                short_msg = short_msg.replace("access logging", "log")
                short_msg = short_msg.replace("object locking", "lock")
                short_msg = short_msg.replace("versioning", "ver")
                bucket_msgs.append(short_msg)

            # Build the annotation message
            annotation = f"Non-compliant KB S3 buckets: {'; '.join(bucket_msgs)}"

            # If annotation exceeds limit, truncate and refer to logs
            if len(annotation) > 256:
                # Log the full message
                LOGGER.info(f"Full compliance details: {annotation}")
                # Create a truncated message that fits within the limit
                count = len(non_compliant_buckets)
                annotation = f"{count} non-compliant KB S3 buckets. See CloudWatch logs for details."

            return "NON_COMPLIANT", annotation
        return "COMPLIANT", "All KB S3 buckets compliant"

    except Exception as e:
        LOGGER.error(f"Error evaluating Knowledge Base S3 bucket configurations: {str(e)}")
        return "ERROR", f"Error: {str(e)[:240]}"


def lambda_handler(event: dict, context: Any) -> None:  # noqa: U100
    """Lambda handler.

    Args:
        event (dict): Lambda event object
        context (Any): Lambda context object
    """
    LOGGER.info("Evaluating compliance for AWS Config rule")
    LOGGER.info(f"Event: {json.dumps(event)}")

    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event["ruleParameters"]) if "ruleParameters" in event else {}

    compliance_type, annotation = evaluate_compliance(rule_parameters)

    evaluation = {
        "ComplianceResourceType": "AWS::::Account",
        "ComplianceResourceId": event["accountId"],
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "OrderingTimestamp": invoking_event["notificationCreationTime"],
    }

    LOGGER.info(f"Compliance evaluation result: {compliance_type}")
    LOGGER.info(f"Annotation: {annotation}")

    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])  # type: ignore[list-item]

    LOGGER.info("Compliance evaluation complete.")
