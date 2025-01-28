"""Config rule to check invocation log s3 enabled for Bedrock environemts.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
import os
from typing import Any

import boto3
import botocore
import botocore.exceptions

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Get AWS region from environment variable
AWS_REGION = os.environ.get("AWS_REGION")

# Initialize AWS clients
bedrock_client = boto3.client("bedrock", region_name=AWS_REGION)
config_client = boto3.client("config", region_name=AWS_REGION)
s3_client = boto3.client("s3", region_name=AWS_REGION)

# Global variables
BUCKET_NAME = ""

def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: CFQ004, CCR001, C901
    """Evaluate if Bedrock Model Invocation Logging is properly configured for S3.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config.

    Returns:
        tuple[str, str]: Compliance status and annotation message.

    """
    global BUCKET_NAME
    # Parse rule parameters
    params = json.loads(json.dumps(rule_parameters)) if rule_parameters else {}
    check_retention = params.get("check_retention", "true").lower() == "true"
    check_encryption = params.get("check_encryption", "true").lower() == "true"
    check_access_logging = params.get("check_access_logging", "true").lower() == "true"
    check_object_locking = params.get("check_object_locking", "true").lower() == "true"
    check_versioning = params.get("check_versioning", "true").lower() == "true"

    try:
        response = bedrock_client.get_model_invocation_logging_configuration()
        logging_config = response.get("loggingConfig", {})

        s3_config = logging_config.get("s3Config", {})
        LOGGER.info(f"Bedrock Model Invocation S3 config: {s3_config}")
        bucket_name = s3_config.get("bucketName", "")
        LOGGER.info(f"Bedrock Model Invocation S3 bucketName: {bucket_name}")
        BUCKET_NAME = bucket_name
        if not s3_config or not bucket_name:
            return "NON_COMPLIANT", "S3 logging is not enabled for Bedrock Model Invocation Logging"

        # Check S3 bucket configurations
        issues = []

        if check_retention:
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                if not any(rule.get("Expiration") for rule in lifecycle.get("Rules", [])):
                    issues.append("retention not set")
            except botocore.exceptions.ClientError as client_error:
                if client_error.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    LOGGER.info(f"No lifecycle configuration found for S3 bucket: {bucket_name}")
                    issues.append("lifecycle not set")

        if check_encryption:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            if "ServerSideEncryptionConfiguration" not in encryption:
                issues.append("encryption not set")

        if check_access_logging:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in logging:
                issues.append("server access logging not enabled")

        if check_versioning:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get("Status") != "Enabled":
                issues.append("versioning not enabled")
        try:
            if check_object_locking:
                object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                if "ObjectLockConfiguration" not in object_lock:
                    issues.append("object locking not enabled")
        except botocore.exceptions.ClientError as error:
            error_code = error.response["Error"]["Code"]
            if error_code == "ObjectLockConfigurationNotFoundError":
                LOGGER.info(f"Object Lock is not enabled for S3 bucket: {bucket_name}")
                issues.append("object locking not enabled")
            else:
                LOGGER.info(f"Error evaluating Object Lock configuration: {str(error)}")
                return "INSUFFICIENT_DATA", f"Error evaluating Object Lock configuration: {str(error)}"

        if issues:
            return "NON_COMPLIANT", f"S3 logging to {BUCKET_NAME} enabled but {', '.join(issues)}"
        return "COMPLIANT", f"S3 logging properly configured for Bedrock Model Invocation Logging. Bucket: {bucket_name}"
    except botocore.exceptions.ClientError as client_error:
        LOGGER.error(f"Error evaluating Bedrock Model Invocation Logging configuration: {str(client_error)}")
        return "INSUFFICIENT_DATA", f"Error evaluating compliance: {str(client_error)}"


def lambda_handler(event: dict, context: Any) -> None:  # noqa: U100
    """Lambda handler.

    Args:
        event (dict): Config event data
        context (Any): Lambda event object
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

    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])

    LOGGER.info("Compliance evaluation complete.")
