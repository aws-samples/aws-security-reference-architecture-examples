"""Config rule to check the eval job S3 bucket for Bedrock environemts.

Version: 1.0

Config rule for SRA in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import ast
import logging
import os
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
DEFAULT_RESOURCE_TYPE = "AWS::S3::Bucket"

# Setup Default Logger
LOGGER = logging.getLogger(__name__)
log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)
LOGGER.info(f"boto3 version: {boto3.__version__}")

# Define the AWS Config rule parameters
RULE_NAME = "sra-bedrock-check-eval-job-bucket"
SERVICE_NAME = "bedrock.amazonaws.com"
BUCKET_NAME = ""


def evaluate_compliance(event: dict, context: Any) -> tuple[str, str]:  # noqa: U100, CCR001, C901
    """Evaluate the S3 bucket for the compliance.

    Args:
        event (dict): The AWS Config event
        context (Any): The AWS Lambda context

    Returns:
        tuple[str, str]: The compliance status and annotation
    """
    global BUCKET_NAME
    LOGGER.info(f"Evaluate Compliance Event: {event}")
    # Initialize AWS clients
    s3 = boto3.client("s3")
    sts = boto3.client("sts")
    session = boto3.Session()
    region = session.region_name
    account = sts.get_caller_identity().get("Account")
    # Get rule parameters
    params = ast.literal_eval(event["ruleParameters"])
    LOGGER.info(f"Parameters: {params}")
    LOGGER.info(f"Account: {account}")
    bucket_prefix = params.get("BucketNamePrefix", "")
    LOGGER.info(f"Bucket Prefix: {bucket_prefix}")
    bucket_name = bucket_prefix + "-" + account + "-" + region
    LOGGER.info(f"Bucket Name: {bucket_name}")
    BUCKET_NAME = bucket_name

    check_retention = params.get("CheckRetention", "true").lower() != "false"
    check_encryption = params.get("CheckEncryption", "true").lower() != "false"
    check_logging = params.get("CheckLogging", "true").lower() != "false"
    check_object_locking = params.get("CheckObjectLocking", "true").lower() != "false"
    check_versioning = params.get("CheckVersioning", "true").lower() != "false"

    # Check if the bucket exists
    if bucket_name == "":
        return build_evaluation("NOT_APPLICABLE", "No bucket name provided")
    if not check_bucket_exists(bucket_name):
        return build_evaluation("NOT_APPLICABLE", f"Bucket {bucket_name} does not exist or is not accessible")

    compliance_type = "COMPLIANT"
    annotation = []

    # Check retention
    if check_retention:
        LOGGER.info(f"Checking retention policy for bucket {bucket_name}")
        try:
            retention = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if not any(rule.get("Expiration") for rule in retention.get("Rules", [])):
                compliance_type = "NON_COMPLIANT"
                annotation.append("Retention policy not set")
        except ClientError:
            compliance_type = "NON_COMPLIANT"
            annotation.append("Retention policy not set")

    # Check encryption
    if check_encryption:
        LOGGER.info(f"Checking encryption for bucket {bucket_name}")
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if "ServerSideEncryptionConfiguration" not in encryption:
                compliance_type = "NON_COMPLIANT"
                annotation.append("KMS customer-managed key encryption not enabled")
        except ClientError:
            compliance_type = "NON_COMPLIANT"
            annotation.append("KMS customer-managed key encryption not enabled")

    # Check logging
    if check_logging:
        LOGGER.info(f"Checking logging for bucket {bucket_name}")
        logging = s3.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging:
            compliance_type = "NON_COMPLIANT"
            annotation.append("Server access logging not enabled")

    # Check object locking
    if check_object_locking:
        LOGGER.info(f"Checking object locking for bucket {bucket_name}")
        try:
            object_locking = s3.get_object_lock_configuration(Bucket=bucket_name)
            if "ObjectLockConfiguration" not in object_locking:
                compliance_type = "NON_COMPLIANT"
                annotation.append("Object locking not enabled")
        except ClientError:
            compliance_type = "NON_COMPLIANT"
            annotation.append("Object locking not enabled")

    # Check versioning
    if check_versioning:
        LOGGER.info(f"Checking versioning for bucket {bucket_name}")
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") != "Enabled":
            compliance_type = "NON_COMPLIANT"
            annotation.append("Versioning not enabled")

    annotation_str = "; ".join(annotation) if annotation else "All checked features are compliant"
    return build_evaluation(compliance_type, annotation_str)


def check_bucket_exists(bucket_name: str) -> Any:
    """Check if the bucket exists and is accessible.

    Args:
        bucket_name (str): The name of the bucket to check

    Returns:
        Any: True if the bucket exists and is accessible, False otherwise
    """
    s3 = boto3.client("s3")
    try:
        response = s3.list_buckets()
        buckets = [bucket["Name"] for bucket in response["Buckets"]]
        return bucket_name in buckets
    except ClientError as e:
        LOGGER.info(f"An error occurred: {e}")
        return False


def build_evaluation(compliance_type: str, annotation: str) -> Any:
    """Build the evaluation compliance type and annotation.

    Args:
        compliance_type (str): The compliance type
        annotation (str): the annotation

    Returns:
        Any: The evaluation compliance type and annotation
    """
    LOGGER.info(f"Build Evaluation Compliance Type: {compliance_type} Annotation: {annotation}")
    return {"ComplianceType": compliance_type, "Annotation": annotation, "OrderingTimestamp": datetime.now().isoformat()}


def lambda_handler(event: dict, context: Any) -> None:
    """Lambda handler.

    Args:
        event (dict): The AWS Config event
        context (Any): The AWS Lambda context
    """
    LOGGER.info(f"Lambda Handler Context: {context}")
    LOGGER.info(f"Lambda Handler Event: {event}")
    evaluation = evaluate_compliance(event, context)
    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": "AWS::S3::Bucket",
                "ComplianceResourceId": BUCKET_NAME,
                "ComplianceType": evaluation["ComplianceType"],  # type: ignore
                "Annotation": evaluation["Annotation"],  # type: ignore
                "OrderingTimestamp": evaluation["OrderingTimestamp"],  # type: ignore
            }
        ],
        ResultToken=event["resultToken"],
    )
