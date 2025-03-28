"""Config rule to check invocation log cloudwatch enabled for Bedrock environemts.

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
logs_client = boto3.client("logs", region_name=AWS_REGION)


def evaluate_compliance(rule_parameters: dict) -> tuple[str, str]:  # noqa: CFQ004
    """Evaluate if Bedrock Model Invocation Logging is properly configured for CloudWatch.

    Args:
        rule_parameters (dict): Rule parameters from AWS Config rule.

    Returns:
        tuple[str, str]: Compliance type and annotation message.
    """
    # Parse rule parameters
    params = json.loads(json.dumps(rule_parameters)) if rule_parameters else {}
    check_retention = params.get("check_retention", "true").lower() == "true"
    check_encryption = params.get("check_encryption", "true").lower() == "true"

    try:
        response = bedrock_client.get_model_invocation_logging_configuration()
        LOGGER.info(f"Bedrock get_model_invocation_logging_configuration response: {response}")
        logging_config = response.get("loggingConfig", {})
        LOGGER.info(f"Bedrock Model Invocation Logging Configuration: {logging_config}")
        cloudwatch_config = logging_config.get("cloudWatchConfig", {})
        LOGGER.info(f"Bedrock Model Invocation config: {cloudwatch_config}")
        log_group_name = cloudwatch_config.get("logGroupName", "")
        LOGGER.info(f"Bedrock Model Invocation Log Group: {log_group_name}")

        if not cloudwatch_config or not log_group_name:
            return "NON_COMPLIANT", "CloudWatch logging is not enabled for Bedrock Model Invocation Logging"

        # Check retention and encryption if enabled
        issues = []
        if check_retention:
            retention = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0].get("retentionInDays")
            if not retention:
                issues.append("retention not set")

        if check_encryption:
            encryption = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0].get("kmsKeyId")
            if not encryption:
                issues.append("encryption not set")

        if issues:
            return "NON_COMPLIANT", f"CloudWatch logging enabled but {', '.join(issues)}"
        return "COMPLIANT", f"CloudWatch logging properly configured for Bedrock Model Invocation Logging. Log Group: {log_group_name}"

    except Exception as e:
        LOGGER.error(f"Error evaluating Bedrock Model Invocation Logging configuration: {str(e)}")
        return "INSUFFICIENT_DATA", f"Error evaluating compliance: {str(e)}"


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

    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])  # type: ignore

    LOGGER.info("Compliance evaluation complete.")
